import os
import time
from pathlib import Path

import httpx
from loguru import logger
from openai import OpenAI


def _load_env_file() -> None:
    env_paths = [Path(__file__).parent / ".env", Path.cwd() / ".env"]
    for env_path in env_paths:
        if not env_path.exists():
            continue
        for raw_line in env_path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :]
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


def _get_bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int_env(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning(f"Invalid int for {name}={value}, fallback to {default}")
        return default


def _get_api_key() -> str:
    env_key = os.environ.get("KGPT_LLM_API_KEY") or os.environ.get(
        "OPENAI_API_KEY"
    )
    if env_key:
        return env_key
    legacy_key_path = Path(__file__).parent / "openai.key"
    if legacy_key_path.exists():
        return legacy_key_path.read_text().strip()
    cfg = _get_llm_config()
    if cfg["base_url"]:
        logger.warning(
            "No API key found, fallback to EMPTY for custom base_url"
        )
        return "EMPTY"
    raise ValueError(
        "No API key found. Please set KGPT_LLM_API_KEY in .env or create spec-gen/openai.key"
    )


_load_env_file()


def _get_llm_config() -> dict:
    return {
        "provider": os.environ.get("KGPT_LLM_PROVIDER", "openai").strip(),
        "model": os.environ.get("KGPT_LLM_MODEL", "gpt-4o-mini").strip(),
        "base_url": os.environ.get("KGPT_LLM_BASE_URL", "").strip(),
        "max_tokens": _get_int_env("KGPT_LLM_MAX_TOKENS", 8192),
        "max_failures": _get_int_env("KGPT_LLM_MAX_FAILURES", 20),
        "retry_sleep_seconds": _get_int_env("KGPT_LLM_RETRY_SLEEP_SECONDS", 10),
        "trust_env": _get_bool_env("KGPT_LLM_TRUST_ENV", False),
        "use_json_response_format": _get_bool_env(
            "KGPT_LLM_USE_JSON_RESPONSE_FORMAT", True
        ),
    }


def _normalize_proxy_env_vars() -> None:
    proxy_keys = [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
    ]
    for key in proxy_keys:
        value = os.environ.get(key)
        if not value:
            continue
        if value.startswith("socks://"):
            os.environ[key] = "socks5://" + value[len("socks://") :]
            logger.warning(
                f"Normalize {key} from socks:// to socks5:// for httpx compatibility"
            )


_CLIENT = None


def _get_client():
    global _CLIENT
    if _CLIENT is not None:
        return _CLIENT

    cfg = _get_llm_config()
    if cfg["trust_env"]:
        _normalize_proxy_env_vars()
    client_kwargs = {
        "api_key": _get_api_key(),
        "timeout": httpx.Timeout(300.0, connect=30.0),
    }
    if cfg["base_url"]:
        client_kwargs["base_url"] = cfg["base_url"]
    client_kwargs["http_client"] = httpx.Client(
        trust_env=cfg["trust_env"],
        timeout=httpx.Timeout(300.0, connect=30.0),
    )

    _CLIENT = OpenAI(**client_kwargs)
    return _CLIENT


system_message = (
    "You are Syzkaller specification generator and "
    "linux kernel source code analyzer."
    "You only reply with JSON."
)


def query_gpt4(prompt: str, temperature=0.1):
    return query_llm(prompt, temperature=temperature)


def query_llm(prompt: str, temperature=0.1, system_message_override: str = None):
    cfg = _get_llm_config()
    client = _get_client()
    model = cfg["model"]
    max_tokens = cfg["max_tokens"]
    failure_count = 0
    content = None
    msg_system = system_message_override if system_message_override is not None else system_message
    while True:
        try:
            logger.info(
                f"Invoke LLM provider={cfg['provider']} model={model} max_tokens={max_tokens}"
            )
            t_start = time.time()
            request_kwargs = {
                "model": model,
                "messages": [
                    {"role": "system", "content": msg_system},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": temperature,
                "n": 1,
            }
            if cfg["use_json_response_format"]:
                request_kwargs["response_format"] = {"type": "json_object"}
            response = client.chat.completions.create(**request_kwargs)
            g_time = time.time() - t_start
            logger.info(f"LLM response time: {g_time}")
            content = response.choices[0].message.content
            if content and content.strip():
                break
            failure_count += 1
            logger.warning(
                f"LLM returned empty content (attempt {failure_count}), retrying..."
            )
        except httpx.TimeoutException as e:
            failure_count += 1
            logger.warning(
                f"LLM request timed out after {time.time() - t_start:.1f}s "
                f"(attempt {failure_count}): {type(e).__name__}"
            )
        except Exception as e:
            failure_count += 1
            logger.info(f"Exception: {e!r}")
            if "maximum context length" in str(e):
                max_tokens = max_tokens // 2
                logger.info(f"Reduce max_tokens to {max_tokens}")
        if failure_count > cfg["max_failures"]:
            logger.error("Too many failures, skip this prompt")
            break
        time.sleep(cfg["retry_sleep_seconds"])
    if failure_count > cfg["max_failures"]:
        return None
    return content
