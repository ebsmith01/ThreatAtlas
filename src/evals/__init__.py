"""Evaluation routines for the attack corpus."""

__all__ = ["run_eval"]


def run_eval(*args, **kwargs):
    from .generate_report import run_eval as _run_eval

    return _run_eval(*args, **kwargs)
