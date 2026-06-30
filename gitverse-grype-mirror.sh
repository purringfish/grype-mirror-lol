#!/usr/bin/env bash
#
# gitverse-grype-mirror.sh
# Зеркалит grype v6 vulnerability-db В САМ РЕПОЗИТОРИЙ GitVerse (через git push),
# а не в generic-реестр пакетов.
#
# Почему git push, а не API: у GitVerse REST API репозитория доступен только на ЧТЕНИЕ
# (contents PUT -> 401, releases/tags POST -> 404, даже полным токеном). Запись в репозиторий
# возможна лишь обычным git-пушем по HTTPS — он работает и токеном авторизуется.
#
# GitVerse держит лимит ~100 МБ/файл, а архив базы ~123 МБ, поэтому архив РЕЖЕТСЯ на части
# по ~90 МБ (split) и кладётся файлами в репозиторий. Рядом — index.json (имя архива, sha256,
# список частей).
#
# Раскладка: отдельная ветка $GV_BRANCH (по умолчанию "db"), которую КАЖДЫЙ прогон
# пересоздаёт как orphan (без истории) и пушит с -f. Так в репозитории всегда лежит ровно
# одна (актуальная) сборка, а прежняя затирается — место не растёт. Файлы видны в репозитории
# и отдаются анонимно по raw-URL:
#   https://gitverse.ru/api/repos/<owner>/<repo>/raw/branch/<branch>/index.json
#   https://gitverse.ru/api/repos/<owner>/<repo>/raw/branch/<branch>/<архив>.tar.zst.part00
#
set -euo pipefail

# ----------------------------- НАСТРОЙКИ -------------------------------------
# Ник, репозиторий и токен GitVerse в скрипте НЕ хранятся — только из окружения
# (в GitHub Actions это secrets.GV_OWNER / secrets.GV_REPO / secrets.GV_TOKEN).
GV_OWNER="${GV_OWNER:?нужен GV_OWNER — ник GitVerse (в CI secrets.GV_OWNER)}"
GV_TOKEN="${GV_TOKEN:?нужен GV_TOKEN — токен GitVerse (в CI secrets.GV_TOKEN)}"
GV_REPO="${GV_REPO:?нужен GV_REPO — репозиторий GitVerse (в CI secrets.GV_REPO)}"
GV_BRANCH="${GV_BRANCH:-db}"                          # ветка-хранилище базы (orphan, force-push)
PART_SIZE=80m                                         # размер куска; ВАЖНО: GitVerse режет и размер
                                                     # одного git-push (~100 МБ, HTTP 413), поэтому
                                                     # ниже каждая часть пушится отдельным коммитом

UPSTREAM="https://grype.anchore.io/databases/v6"     # официальный источник v6
GV_HOST="gitverse.ru"
# -----------------------------------------------------------------------------

export GV_OWNER GV_TOKEN                              # нужны askpass-скрипту
RAWBASE="https://$GV_HOST/api/repos/$GV_OWNER/$GV_REPO/raw/branch/$GV_BRANCH"
WORKDIR="$(mktemp -d)"; trap 'rm -rf "$WORKDIR"' EXIT
DRY_RUN="${DRY_RUN:-0}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# --- 1. Скачать манифест и архив с anchore -----------------------------------
log "Качаю официальный latest.json..."
wget -q -O "$WORKDIR/upstream.json" "$UPSTREAM/latest.json"

read -r ARCHIVE_PATH CHECKSUM BUILT SCHEMA < <(python3 - "$WORKDIR/upstream.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(d["path"],d["checksum"],d["built"],d["schemaVersion"])
PY
)
ARCHIVE_NAME="$(basename "$ARCHIVE_PATH")"
SAFE_NAME="${ARCHIVE_NAME//:/-}"        # URL-безопасное имя (двоеточия -> дефисы)
BASE="${SAFE_NAME%.tar.zst}"
BUILD_ID="${BASE##*_}"                   # уникальный id сборки (хвостовое число)
log "Версия: $SCHEMA | сборка: $BUILT | build_id: $BUILD_ID"
log "Архив: $ARCHIVE_NAME"

log "Качаю архив базы (~123 МБ)..."
wget -q -O "$WORKDIR/$SAFE_NAME" "$UPSTREAM/$ARCHIVE_PATH"

log "Проверяю sha256..."
WANT="${CHECKSUM#sha256:}"
GOT="$(sha256sum "$WORKDIR/$SAFE_NAME" | awk '{print $1}')"
[[ "$WANT" == "$GOT" ]] || { echo "sha256 не совпала! want=$WANT got=$GOT" >&2; exit 1; }
log "sha256 ОК | размер: $(du -h "$WORKDIR/$SAFE_NAME" | awk '{print $1}')"

# --- 2. Нарезать на части по PART_SIZE ----------------------------------------
PAYLOAD="$WORKDIR/payload"; mkdir -p "$PAYLOAD"
log "Режу архив на части по $PART_SIZE..."
( cd "$PAYLOAD" && split -b "$PART_SIZE" -d -a 2 "$WORKDIR/$SAFE_NAME" "$SAFE_NAME.part" )
PARTS=()
while IFS= read -r p; do PARTS+=("$(basename "$p")"); done \
  < <(find "$PAYLOAD" -maxdepth 1 -name "$SAFE_NAME.part*" | sort)
log "Частей: ${#PARTS[@]} -> ${PARTS[*]}"

# index.json (формат, который понимает клиент grype-db-pull.sh: builds[0])
python3 - "$PAYLOAD/index.json" "$BUILD_ID" "$SAFE_NAME" "sha256:$WANT" "$SCHEMA" "$BUILT" "${PARTS[@]}" <<'PY'
import json,sys
out,bid,name,checksum,schema,built,*parts=sys.argv[1:]
json.dump({"builds":[{"id":bid,"name":name,"checksum":checksum,
                      "schema":schema,"built":built,"parts":parts}]},
          open(out,"w"),indent=2,ensure_ascii=False)
PY

if [[ "$DRY_RUN" == "1" ]]; then
  log "DRY_RUN=1 — в GitVerse ничего не пушу. index.json:"
  cat "$PAYLOAD/index.json"; echo
  exit 0
fi

# --- 3. Залить в репозиторий: orphan-ветка $GV_BRANCH + force-push -------------
# askpass: отдаёт git'у логин/токен из окружения, чтобы токен не светился в URL/командах
ASKPASS="$WORKDIR/askpass.sh"
cat > "$ASKPASS" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  *[Uu]sername*) printf '%s' "$GV_OWNER" ;;
  *[Pp]assword*) printf '%s' "$GV_TOKEN" ;;
esac
EOF
chmod 700 "$ASKPASS"
export GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0

REMOTE="https://$GV_HOST/$GV_OWNER/$GV_REPO.git"      # БЕЗ токена в URL
CLONE="$WORKDIR/repo"
gitq() {  # git с показом stderr при сбое (а не в /dev/null)
  git "$@" 2>"$WORKDIR/git.err" || { echo "git $* — ошибка:" >&2; cat "$WORKDIR/git.err" >&2; return 1; }
}
log "Клонирую репозиторий (поверхностно, только дефолтная ветка)..."
gitq clone --depth 1 "$REMOTE" "$CLONE" >/dev/null

cd "$CLONE"
git config user.email "ci@grype-mirror"
git config user.name  "grype-db mirror"

log "Собираю orphan-ветку '$GV_BRANCH' с текущей сборкой..."
gitq checkout --orphan "$GV_BRANCH" >/dev/null
git rm -rf . >/dev/null 2>&1 || true                 # очистить дерево от файлов дефолтной ветки

# GitVerse ограничивает размер ОДНОГО git-push (~100 МБ, иначе HTTP 413), поэтому каждую
# часть кладём отдельным коммитом и пушим по очереди — в пак уходит только новая часть.
# Первый push идёт с -f (сбрасывает ветку до новой orphan-сборки, старая затирается),
# остальные — обычным fast-forward'ом.
first=1
for p in "${PARTS[@]}"; do
  cp "$PAYLOAD/$p" .
  git add "$p"
  git commit -q -m "grype db $BUILD_ID: $p"
  if [[ "$first" == 1 ]]; then
    log "Пушу '$GV_BRANCH' с force: $p (сброс ветки)..."
    gitq push -f origin "HEAD:$GV_BRANCH" >/dev/null
    first=0
  else
    log "Дозаливаю в '$GV_BRANCH': $p..."
    gitq push origin "HEAD:$GV_BRANCH" >/dev/null
  fi
done
# index.json — последним коммитом (маленький)
cp "$PAYLOAD/index.json" .
git add index.json
git commit -q -m "grype db $BUILD_ID: index.json"
log "Дозаливаю index.json..."
gitq push origin "HEAD:$GV_BRANCH" >/dev/null
cd /

# --- 4. Самопроверка: index.json отдаётся анонимно по raw ----------------------
# (целые части не качаем — это лишние ~120 МБ на каждый прогон; их целостность
#  всё равно проверит клиент по sha256 всего архива.)
log "Проверяю, что index.json отдаётся по raw..."
curl -fsS "$RAWBASE/index.json?nocache=$(date +%s%N)" -o "$WORKDIR/chk.json" \
  && log "OK index.json: $(tr -d '\n' <"$WORKDIR/chk.json" | cut -c1-90)..."

log "Готово! База лежит в репозитории GitVerse, ветка '$GV_BRANCH':"
echo "  $RAWBASE/"
echo "Клиент (grype-db-pull.sh) сначала пробует GitHub, затем — эту ветку GitVerse."
