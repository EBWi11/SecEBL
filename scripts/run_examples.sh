#!/usr/bin/env bash
# Run the public SecEBL example-data path: L1 predictions, L1 gold metrics,
# and optional L2 session scoring when an L2 model artifact is available.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

PY="${PY:-python3}"
MODEL_DIR="${MODEL_DIR:-model_artifacts}"
DATA_DIR="${DATA_DIR:-${MODEL_DIR}}"
OUT_DIR="${OUT_DIR:-runs/examples}"
DEVICE="${DEVICE:-auto}"
MAX_SEQ_LENGTH="${MAX_SEQ_LENGTH:-160}"
SHOW_PROGRESS="${SHOW_PROGRESS:-1}"

if [[ "${DEVICE}" == "auto" ]]; then
  DEVICE="$("${PY}" - <<'PY'
try:
    import torch
    if torch.cuda.is_available():
        print("cuda")
    elif getattr(torch.backends, "mps", None) is not None and torch.backends.mps.is_available():
        print("mps")
    else:
        print("cpu")
except Exception:
    print("cpu")
PY
)"
fi

if [[ -z "${BATCH_SIZE:-}" ]]; then
  case "${DEVICE}" in
    cuda) BATCH_SIZE=224 ;;
    mps) BATCH_SIZE=64 ;;
    *) BATCH_SIZE=32 ;;
  esac
fi

CALIBRATION="${CALIBRATION:-}"
if [[ -z "${CALIBRATION}" && -s "${MODEL_DIR}/score_calibration.rev20.json" ]]; then
  CALIBRATION="${MODEL_DIR}/score_calibration.rev20.json"
fi

common_l1_args=(
  --model "${MODEL_DIR}"
  --data-dir "${DATA_DIR}"
  --device "${DEVICE}"
  --batch-size "${BATCH_SIZE}"
  --max-seq-length "${MAX_SEQ_LENGTH}"
  --save-top-k 5
  --prompt-profile mid
)
if [[ -n "${CALIBRATION}" ]]; then
  common_l1_args+=(--calibration "${CALIBRATION}")
fi
if [[ "${SHOW_PROGRESS}" == "1" ]]; then
  common_l1_args+=(--show-progress-bar)
fi

mkdir -p "${OUT_DIR}/linux_l1" "${OUT_DIR}/k8s_l1" "${OUT_DIR}/l2"

echo "== SecEBL example-data run =="
echo "model=${MODEL_DIR} data=${DATA_DIR} device=${DEVICE} batch_size=${BATCH_SIZE} out=${OUT_DIR}"

echo "== L1 Linux public example gold =="
"${PY}" secebl_l1/predict_benchmark_tags.py \
  --benchmark examples/linux/example_gold.rev20.jsonl \
  --out-dir "${OUT_DIR}/linux_l1" \
  "${common_l1_args[@]}"
"${PY}" secebl_l1/eval_rev20_final_gold.py \
  --gold examples/linux/example_gold.rev20.jsonl \
  --predictions "${OUT_DIR}/linux_l1/predictions.jsonl" \
  --out "${OUT_DIR}/linux_l1/top5_tag_accuracy.json"

echo "== L1 K8s public example gold =="
"${PY}" secebl_l1/predict_benchmark_tags.py \
  --benchmark examples/k8s/example_gold.rev20.jsonl \
  --out-dir "${OUT_DIR}/k8s_l1" \
  "${common_l1_args[@]}"
"${PY}" secebl_l1/eval_rev20_final_gold.py \
  --gold examples/k8s/example_gold.rev20.jsonl \
  --predictions "${OUT_DIR}/k8s_l1/predictions.jsonl" \
  --out "${OUT_DIR}/k8s_l1/top5_tag_accuracy.json"

L2_MODEL="${L2_MODEL:-}"
if [[ -z "${L2_MODEL}" ]]; then
  for candidate in \
    "l2_artifacts/logreg.joblib" \
    "${MODEL_DIR}/l2_artifacts/logreg.joblib" \
    "${MODEL_DIR}/l2/logreg.joblib" \
    "${MODEL_DIR}/logreg.joblib"; do
    if [[ -s "${candidate}" ]]; then
      L2_MODEL="${candidate}"
      break
    fi
  done
fi

if [[ -n "${L2_MODEL}" && -s "${L2_MODEL}" ]]; then
  echo "== L2 Linux public example sessions =="
  l2_args=(
    score
    --input examples/linux/example_sessions.jsonl \
    --predictions "${OUT_DIR}/linux_l1/predictions.jsonl" \
    --risk-policy secebl_l2/tag_risk_policy.rev20.json \
    --model "${L2_MODEL}" \
    --output "${OUT_DIR}/l2/example_linux_session_results.json" \
    --alerts-out "${OUT_DIR}/l2/example_linux_alerts.jsonl"
  )
  if [[ -n "${CALIBRATION}" ]]; then
    l2_args+=(--calibration "${CALIBRATION}")
  fi
  "${PY}" secebl_l2/rev20_l2_ml.py "${l2_args[@]}"
else
  echo "== L2 skipped: set L2_MODEL=/path/to/logreg.joblib to score example sessions =="
fi

echo "== done =="
echo "Linux L1: ${OUT_DIR}/linux_l1/top5_tag_accuracy.json"
echo "K8s L1:   ${OUT_DIR}/k8s_l1/top5_tag_accuracy.json"
if [[ -n "${L2_MODEL}" && -s "${L2_MODEL}" ]]; then
  echo "L2:        ${OUT_DIR}/l2/example_linux_session_results.json"
fi
