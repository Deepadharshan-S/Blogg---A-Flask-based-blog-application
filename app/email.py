import logging
import os
import queue
import threading
from concurrent.futures import Future

from flask import current_app, render_template
from flask_mail import Message

from . import mail

logger = logging.getLogger(__name__)

_email_executor = None


class EmailQueueFull(Exception):
    """Raised when the bounded email queue capacity is exceeded."""

    pass


class BoundedEmailExecutor:
    """Bounded worker pool for asynchronous email dispatch.

    Unlike standard ThreadPoolExecutor which backs itself with an unbounded
    queue.SimpleQueue, BoundedEmailExecutor uses a fixed-capacity queue.Queue.
    When the queue is saturated, tasks are rejected immediately without
    blocking caller request threads or spawning unbounded threads, preventing
    resource exhaustion (DoS) attacks.
    """

    def __init__(self, max_workers: int = 4, max_queue_size: int = 50):
        self._max_workers = max(1, int(max_workers))
        self._max_queue_size = max(1, int(max_queue_size))
        self._queue: queue.Queue = queue.Queue(maxsize=self._max_queue_size)
        self._threads: list[threading.Thread] = []
        self._shutdown = False
        self._lock = threading.Lock()
        self._start_workers()

    def _start_workers(self):
        with self._lock:
            for i in range(self._max_workers):
                t = threading.Thread(
                    target=self._worker_loop,
                    name=f"email-worker-{i}",
                    daemon=True,
                )
                t.start()
                self._threads.append(t)

    def _worker_loop(self):
        while not self._shutdown:
            try:
                task = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if task is None:
                self._queue.task_done()
                break

            fn, args, kwargs, future = task
            try:
                result = fn(*args, **kwargs)
                if future and not future.done():
                    future.set_result(result)
            except Exception as exc:
                if future and not future.done():
                    future.set_exception(exc)
            finally:
                self._queue.task_done()

    def submit(self, fn, *args, **kwargs) -> Future:
        """Submit a callable to the bounded worker queue.

        Raises EmailQueueFull if the queue is saturated.
        """
        if self._shutdown:
            raise RuntimeError("Cannot submit to shutdown executor")

        future = Future()
        try:
            self._queue.put_nowait((fn, args, kwargs, future))
            return future
        except queue.Full:
            future.set_exception(EmailQueueFull("Email queue is full"))
            raise EmailQueueFull(f"Email queue is full (capacity: {self._max_queue_size})")

    def shutdown(self, wait: bool = True):
        """Shut down worker threads."""
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
            for _ in self._threads:
                try:
                    self._queue.put_nowait(None)
                except queue.Full:
                    pass

        if wait:
            for t in self._threads:
                t.join(timeout=2.0)

    @property
    def qsize(self) -> int:
        return self._queue.qsize()

    @property
    def capacity(self) -> int:
        return self._max_queue_size


def get_email_executor(max_workers=None, queue_capacity=None) -> BoundedEmailExecutor:
    global _email_executor
    if _email_executor is None:
        if max_workers is None:
            try:
                max_workers = int(
                    current_app.config.get("BLOGG_EMAIL_MAX_WORKERS")
                    or os.environ.get("BLOGG_EMAIL_MAX_WORKERS", "4")
                )
            except (RuntimeError, ValueError, TypeError):
                max_workers = 4

        if queue_capacity is None:
            try:
                queue_capacity = int(
                    current_app.config.get("BLOGG_EMAIL_QUEUE_CAPACITY")
                    or os.environ.get("BLOGG_EMAIL_QUEUE_CAPACITY", "50")
                )
            except (RuntimeError, ValueError, TypeError):
                queue_capacity = 50

        _email_executor = BoundedEmailExecutor(
            max_workers=max_workers, max_queue_size=queue_capacity
        )
    return _email_executor


def reset_email_executor():
    """Tear down and clear the global email executor (primarily for testing)."""
    global _email_executor
    if _email_executor is not None:
        _email_executor.shutdown(wait=False)
        _email_executor = None


def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Failed to send email: {e}", exc_info=True)


def send_email(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    prefix = app.config.get("BLOGG_MAIL_SUBJECT_PREFIX", "[BLOGG]").strip()
    msg = Message(
        subject=f"{prefix} {subject}",
        sender=app.config["BLOGG_MAIL_SENDER"],
        recipients=[to],
    )
    msg.body = render_template(template + ".txt", **kwargs)
    msg.html = render_template(template + ".html", **kwargs)

    executor = get_email_executor()
    try:
        return executor.submit(send_async_email, app, msg)
    except EmailQueueFull:
        app.logger.warning(
            "Email task queue is saturated (capacity: %d). Dropped outbound email to %s (subject: '%s').",
            executor.capacity,
            to,
            subject,
        )
        return None
    except Exception as e:
        app.logger.error(f"Failed to submit email task to executor: {e}", exc_info=True)
        return None
