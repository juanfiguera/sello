from __future__ import annotations

import inspect
import json
import os
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Union
from urllib.request import urlopen

from . import logs
from .keys import normalize_ed25519_public_key, normalize_service_key
from .receipt import BuiltReceipt, build_receipt, canonical_json_bytes
from .token import verify_sello_jws_token


class SelloDeniedError(Exception):
    def __init__(self, receipt: BuiltReceipt):
        super().__init__("Sello request denied")
        self.receipt = receipt


@dataclass
class _ResolvedConfig:
    service: str
    service_kid: bytes
    service_private_key: bytes
    token_issuer_public_key: bytes
    log: Union[logs.MemoryLog, logs.HttpLog]
    fallback_sello_logs: list[str]
    submit_mode: str
    now: Callable[[], str]
    on_receipt: Optional[Callable[[dict[str, Any]], None]]
    on_submit_error: Optional[Callable[[BaseException], None]]
    on_drop: Optional[Callable[[dict[str, Any]], None]]
    max_pending: int
    concurrency: int


class SelloReceipts:
    def __init__(self, config: _ResolvedConfig):
        self._config = config
        self._executor = ThreadPoolExecutor(max_workers=config.concurrency)
        self._futures: list[Future[Any]] = []

    def tool(self, action_type: str, handler: Optional[Callable[..., Any]] = None, **options: Any):
        if not action_type:
            raise ValueError("Sello action type must be a non-empty string")

        def decorate(fn: Callable[..., Any]):
            if inspect.iscoroutinefunction(fn):
                async def async_wrapped(request: Any):
                    return await self._run_async(action_type, fn, request, options)
                return async_wrapped

            def wrapped(request: Any):
                return self._run_sync(action_type, fn, request, options)
            return wrapped

        return decorate(handler) if handler is not None else decorate

    def flush(self) -> None:
        futures = list(self._futures)
        self._futures.clear()
        if futures:
            wait(futures)

    async def _run_async(self, action_type: str, handler: Callable[[Any], Any], request: Any, options: dict[str, Any]):
        base = self._base(action_type, request, options)
        if await _maybe_await(options.get("is_denied", lambda _: False)(request)):
            response = await _maybe_await(options["denied_response"](request)) if "denied_response" in options else None
            receipt = self._emit(base, b"", "denied")
            if "denied_response" not in options:
                raise SelloDeniedError(receipt)
            return response
        try:
            response = await handler(request)
        except Exception as error:
            self._emit(base, _error_bytes(error, options), "error", error=error)
            raise
        self._emit(base, _output_bytes(response, options), "success", response=response)
        return response

    def _run_sync(self, action_type: str, handler: Callable[[Any], Any], request: Any, options: dict[str, Any]):
        base = self._base(action_type, request, options)
        if options.get("is_denied", lambda _: False)(request):
            response = options["denied_response"](request) if "denied_response" in options else None
            receipt = self._emit(base, b"", "denied")
            if "denied_response" not in options:
                raise SelloDeniedError(receipt)
            return response
        try:
            response = handler(request)
        except Exception as error:
            self._emit(base, _error_bytes(error, options), "error", error=error)
            raise
        self._emit(base, _output_bytes(response, options), "success", response=response)
        return response

    def _base(self, action_type: str, request: Any, options: dict[str, Any]) -> dict[str, Any]:
        token = _resolve_authorization_token(request, options)
        verified = verify_sello_jws_token(token, self._config.token_issuer_public_key)
        sello_logs = verified.sello_logs or self._config.fallback_sello_logs
        if self._config.log.log_url not in sello_logs:
            raise ValueError("Sello log must be listed in the token's sello_logs")
        return {
            "authorization_token_bytes": verified.authorization_token_bytes,
            "owner_hpke_public_key": verified.owner_hpke_public_key,
            "sello_logs": sello_logs,
            "action_type": action_type,
            "action_input_bytes": _input_bytes(request, options),
            "timestamp": self._config.now(),
        }

    def _emit(self, base: dict[str, Any], action_output_bytes: bytes, result_status: str, response: Any = None, error: Optional[BaseException] = None) -> BuiltReceipt:
        receipt = build_receipt(
            **base,
            action_output_bytes=action_output_bytes,
            result_status=result_status,
            service_kid=self._config.service_kid,
            service_private_key=self._config.service_private_key,
            service_identifier=self._config.service,
            log_url=self._config.log.log_url,
        )
        if self._config.on_receipt:
            event = {"result_status": result_status, "receipt": receipt}
            if response is not None:
                event["response"] = response
            if error is not None:
                event["error"] = error
            self._config.on_receipt(event)
        self._submit(receipt.envelope, base["timestamp"])
        return receipt

    def _submit(self, envelope: bytes, integrated_time: str) -> None:
        if self._config.submit_mode == "await":
            self._config.log.append(envelope, integrated_time)
            return
        self._futures = [future for future in self._futures if not future.done()]
        if len(self._futures) >= self._config.max_pending:
            if self._config.on_drop:
                self._config.on_drop({"envelope": envelope, "integrated_time": integrated_time, "reason": "queue_full"})
            return
        future = self._executor.submit(self._config.log.append, envelope, integrated_time)
        if self._config.on_submit_error:
            future.add_done_callback(lambda done: done.exception() and self._config.on_submit_error(done.exception()))
        self._futures.append(future)


def service(config: Optional[Union[str, dict[str, Any]]] = None, **kwargs: Any) -> SelloReceipts:
    values: dict[str, Any] = {}
    if isinstance(config, str):
        values["service"] = config
    elif isinstance(config, dict):
        values.update(config)
    elif config is not None:
        raise ValueError("service config must be a service id string or dict")
    values.update(kwargs)
    return SelloReceipts(_resolve_config(values, os.environ))


def _resolve_config(values: dict[str, Any], env: os._Environ[str]) -> _ResolvedConfig:
    service_id = values.get("service") or env.get("SELLO_SERVICE_ID")
    if not service_id:
        raise ValueError("Sello setup missing SELLO_SERVICE_ID")
    service_kid, service_private_key = normalize_service_key(
        values.get("service_key") or env.get("SELLO_SERVICE_KEY"),
        values.get("service_kid") or env.get("SELLO_SERVICE_KID"),
    )
    log = values.get("log")
    if log is None:
        log_url = env.get("SELLO_LOG_URL")
        if not log_url:
            raise ValueError("Sello setup missing SELLO_LOG_URL")
        log = logs.http(log_url, endpoint=env.get("SELLO_LOG_ENDPOINT"))
    issuer = values.get("token_issuer") or values.get("token_issuer_public_key") or env.get("SELLO_TOKEN_ISSUER_PUBLIC_KEY")
    if issuer is None:
        jwks = values.get("token_issuer_jwks") or env.get("SELLO_TOKEN_ISSUER_JWKS")
        if not jwks:
            raise ValueError("Sello setup missing token issuer")
        issuer = _fetch_jwks_ed25519_public_key(jwks)
    submit = values.get("submit") or env.get("SELLO_SUBMIT_MODE") or "background"
    submit_mode = submit.get("mode", "background") if isinstance(submit, dict) else submit
    return _ResolvedConfig(
        service=str(service_id),
        service_kid=service_kid,
        service_private_key=service_private_key,
        token_issuer_public_key=normalize_ed25519_public_key(issuer, "token_issuer"),
        log=log,
        fallback_sello_logs=values.get("fallback_sello_logs") or [log.log_url],
        submit_mode=submit_mode,
        now=values.get("now") or _now_utc_seconds,
        on_receipt=values.get("on_receipt"),
        on_submit_error=values.get("on_submit_error"),
        on_drop=values.get("on_drop"),
        max_pending=(submit.get("max_pending", 1000) if isinstance(submit, dict) else 1000),
        concurrency=(submit.get("concurrency", 4) if isinstance(submit, dict) else 4),
    )


def _resolve_authorization_token(request: Any, options: dict[str, Any]) -> Union[str, bytes]:
    source = options.get("authorization_token")
    if callable(source):
        return source(request)
    if source is not None:
        return source
    if isinstance(request, dict):
        token = request.get("authorizationToken") or request.get("authorization")
        if token:
            return _strip_bearer(token)
        headers = request.get("headers")
        if isinstance(headers, dict):
            token = headers.get("authorization") or headers.get("Authorization")
            if token:
                return _strip_bearer(token)
    raise ValueError("Sello authorization token not found")


def _strip_bearer(value: Union[str, bytes]) -> Union[str, bytes]:
    if isinstance(value, str) and value.startswith("Bearer "):
        return value[len("Bearer "):]
    return value


def _input_bytes(request: Any, options: dict[str, Any]) -> bytes:
    canonicalizer = options.get("canonicalize_input")
    return canonicalizer(request) if canonicalizer else canonical_json_bytes(request)


def _output_bytes(response: Any, options: dict[str, Any]) -> bytes:
    canonicalizer = options.get("canonicalize_output")
    return canonicalizer(response) if canonicalizer else canonical_json_bytes(response)


def _error_bytes(error: BaseException, options: dict[str, Any]) -> bytes:
    canonicalizer = options.get("canonicalize_error")
    return canonicalizer(error) if canonicalizer else canonical_json_bytes({"name": error.__class__.__name__, "message": str(error)})


def _now_utc_seconds() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _fetch_jwks_ed25519_public_key(jwks_url: str) -> bytes:
    with urlopen(jwks_url) as response:
        jwks = json.loads(response.read().decode("utf-8"))
    for key in jwks.get("keys", []):
        if key.get("kty") == "OKP" and key.get("crv") == "Ed25519" and isinstance(key.get("x"), str):
            from ._crypto import base64url_decode
            return base64url_decode(key["x"], "JWKS x")
    raise ValueError("token issuer JWKS must contain an Ed25519 OKP key")
