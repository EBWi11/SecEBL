"""Model-loading helpers shared by rev20 embedding scripts."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def model_kwargs_from_env() -> dict[str, Any]:
    """Return Hugging Face model kwargs requested by the runtime environment."""

    attn_implementation = os.environ.get("REV20_MODEL_ATTN_IMPLEMENTATION") or os.environ.get(
        "MODEL_ATTN_IMPLEMENTATION"
    )
    if not attn_implementation:
        return {}
    return {"attn_implementation": attn_implementation}


def sentence_transformer_kwargs_from_env() -> dict[str, Any]:
    model_kwargs = model_kwargs_from_env()
    if not model_kwargs:
        return {}
    return {"model_kwargs": model_kwargs}


def configure_torch_float32_matmul() -> None:
    """Optionally prefer TF32-capable float32 matmul on modern NVIDIA GPUs."""

    if os.environ.get("REV20_ENABLE_TF32", "").lower() not in {"1", "true", "yes", "on"}:
        return

    try:
        import torch
    except Exception:
        return

    cuda_backend = getattr(getattr(torch, "backends", None), "cuda", None)
    matmul_backend = getattr(cuda_backend, "matmul", None)
    if matmul_backend is not None and hasattr(matmul_backend, "fp32_precision"):
        try:
            matmul_backend.fp32_precision = "tf32"
            return
        except Exception:
            pass

    try:
        torch.set_float32_matmul_precision("high")
    except Exception:
        return


def load_sentence_transformer(model_name_or_path: str | Path, *, device: str | None = None):
    configure_torch_float32_matmul()
    from sentence_transformers import SentenceTransformer

    kwargs = sentence_transformer_kwargs_from_env()
    if device and device != "auto":
        kwargs["device"] = device
    return SentenceTransformer(str(model_name_or_path), **kwargs)
