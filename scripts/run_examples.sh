#!/usr/bin/env bash
# Run the public SecEBL benchmark-subset example path: L1 predictions, L1 gold
# metrics, and optional L2 session scoring when an L2 model artifact is available.
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
REQUESTED_L2_MODEL="${L2_MODEL:-}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

check_release_artifacts() {
  local missing_text=""
  local missing_count=0

  add_missing() {
    local candidate="$1"
    case "
${missing_text}" in
      *"
${candidate}
"*) return ;;
    esac
    missing_text="${missing_text}${candidate}
"
    missing_count=$((missing_count + 1))
  }

  [[ -d "${MODEL_DIR}" ]] || add_missing "${MODEL_DIR}/"
  [[ -d "${DATA_DIR}" ]] || add_missing "${DATA_DIR}/"
  [[ -s "${DATA_DIR}/semantic_texts.jsonl" ]] || add_missing "${DATA_DIR}/semantic_texts.jsonl"
  [[ -s "${MODEL_DIR}/modules.json" ]] || add_missing "${MODEL_DIR}/modules.json"
  [[ -s "${MODEL_DIR}/config.json" ]] || add_missing "${MODEL_DIR}/config.json"
  if [[ ! -s "${MODEL_DIR}/model.safetensors" && ! -s "${MODEL_DIR}/pytorch_model.bin" ]]; then
    add_missing "${MODEL_DIR}/model.safetensors or ${MODEL_DIR}/pytorch_model.bin"
  fi

  if (( missing_count > 0 )); then
    {
      echo "SecEBL model artifacts are missing."
      echo
      echo "This script does not download model weights automatically. Download the"
      echo "Hugging Face release first, then re-run this script:"
      echo
      echo "  git lfs install"
      echo "  git clone https://huggingface.co/willchen0011/SecEBL model_artifacts"
      echo "  scripts/run_examples.sh"
      echo
      echo "Or point MODEL_DIR/DATA_DIR at an existing artifact directory:"
      echo
      echo "  MODEL_DIR=/path/to/model_artifacts DATA_DIR=/path/to/model_artifacts scripts/run_examples.sh"
      echo
      echo "Missing required artifact(s):"
      while IFS= read -r item; do
        [[ -n "${item}" ]] && printf '  - %s\n' "${item}"
      done <<< "${missing_text}"
    } >&2
    exit 1
  fi

  if [[ -n "${REQUESTED_L2_MODEL}" && ! -s "${REQUESTED_L2_MODEL}" ]]; then
    die "L2_MODEL=${REQUESTED_L2_MODEL} does not exist or is empty"
  fi
}

check_release_artifacts

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

common_l1_args=(
  --model "${MODEL_DIR}"
  --data-dir "${DATA_DIR}"
  --device "${DEVICE}"
  --batch-size "${BATCH_SIZE}"
  --max-seq-length "${MAX_SEQ_LENGTH}"
  --save-top-k 5
  --prompt-profile mid
)
if [[ "${SHOW_PROGRESS}" == "1" ]]; then
  common_l1_args+=(--show-progress-bar)
fi

mkdir -p "${OUT_DIR}/linux_l1" "${OUT_DIR}/k8s_l1" "${OUT_DIR}/l2"

echo "== SecEBL public benchmark-subset example run =="
echo "model=${MODEL_DIR} data=${DATA_DIR} device=${DEVICE} batch_size=${BATCH_SIZE} out=${OUT_DIR}"

echo "== L1 Linux public benchmark-subset gold =="
"${PY}" secebl_l1/predict_benchmark_tags.py \
  --benchmark examples/linux/example_gold.rev20.jsonl \
  --out-dir "${OUT_DIR}/linux_l1" \
  "${common_l1_args[@]}"
"${PY}" secebl_l1/eval_rev20_final_gold.py \
  --gold examples/linux/example_gold.rev20.jsonl \
  --predictions "${OUT_DIR}/linux_l1/predictions.jsonl" \
  --out "${OUT_DIR}/linux_l1/top5_tag_accuracy.json"

echo "== L1 K8s public benchmark-subset gold =="
"${PY}" secebl_l1/predict_benchmark_tags.py \
  --benchmark examples/k8s/example_gold.rev20.jsonl \
  --out-dir "${OUT_DIR}/k8s_l1" \
  "${common_l1_args[@]}"
"${PY}" secebl_l1/eval_rev20_final_gold.py \
  --gold examples/k8s/example_gold.rev20.jsonl \
  --predictions "${OUT_DIR}/k8s_l1/predictions.jsonl" \
  --out "${OUT_DIR}/k8s_l1/top5_tag_accuracy.json"

L2_MODEL="${REQUESTED_L2_MODEL}"
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
  echo "== L2 Linux public benchmark-subset sessions =="
  l2_args=(
    score
    --input examples/linux/example_sessions.jsonl \
    --predictions "${OUT_DIR}/linux_l1/predictions.jsonl" \
    --risk-policy secebl_l2/tag_risk_policy.rev20.json \
    --model "${L2_MODEL}" \
    --output "${OUT_DIR}/l2/example_linux_session_results.json" \
    --alerts-out "${OUT_DIR}/l2/example_linux_alerts.jsonl"
  )
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
