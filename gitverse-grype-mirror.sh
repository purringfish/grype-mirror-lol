#!/usr/bin/env bash
#
# gitverse-grype-mirror.sh
# Зеркалит grype v6 vulnerability-db в GitVerse через generic-реестр пакетов.
#
# GitVerse держит лимит 100 МБ/файл, а архив базы ~123 МБ, поэтому архив РЕЖЕТСЯ
# на части по ~90 МБ (split) и заливается кусками. Рядом кладётся index.json со
# списком частей, контрольной суммой целого архива и историей сборок.
#
# Раскладка (owner=$GV_OWNER, пакет grype-db, версия v6):
#   …/api/packages/<owner>/generic/grype-db/v6/index.json          <- манифест/история
#   …/api/packages/<owner>/generic/grype-db/v6/<архив>.tar.zst.part00
#   …/api/packages/<owner>/generic/grype-db/v6/<архив>.tar.zst.part01
#
# На GitVerse всегда хранится не больше 2 сборок (части старых — удаляются).
#
set -euo pipefail

# ----------------------------- НАСТРОЙКИ -------------------------------------
# Ник, пакет/репозиторий и токен GitVerse в скрипте НЕ хранятся — только из окружения
# (в GitHub Actions это secrets.GV_OWNER / secrets.GV_PKG / secrets.GV_TOKEN).
GV_OWNER="${GV_OWNER:?нужен GV_OWNER — ник GitVerse (в CI secrets.GV_OWNER)}"
GV_TOKEN="${GV_TOKEN:?нужен GV_TOKEN — токен GitVerse (в CI secrets.GV_TOKEN)}"
PKG="${GV_PKG:?нужен GV_PKG — пакет/репозиторий GitVerse (в CI secrets.GV_PKG)}"
VERSEG=v6                                           # сегмент версии в реестре
PART_SIZE=90m                                        # размер куска (< лимита 100 МБ)
KEEP=2                                                # сколько сборок держать на GitVerse

UPSTREAM="https://grype.anchore.io/databases/v6"   # официальный источник v6
# -----------------------------------------------------------------------------

PKGBASE="https://gitverse.ru/api/packages/$GV_OWNER/generic/$PKG/$VERSEG"
AUTH=(-u "$GV_OWNER:$GV_TOKEN")
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
log "Режу архив на части по $PART_SIZE..."
( cd "$WORKDIR" && split -b "$PART_SIZE" -d -a 2 "$SAFE_NAME" "$SAFE_NAME.part" )
PARTS=()
while IFS= read -r p; do PARTS+=("$(basename "$p")"); done \
  < <(find "$WORKDIR" -maxdepth 1 -name "$SAFE_NAME.part*" | sort)
log "Частей: ${#PARTS[@]} -> ${PARTS[*]}"

# собрать запись о текущей сборке (JSON одной строкой)
NEW_BUILD="$(python3 - "$BUILD_ID" "$SAFE_NAME" "sha256:$WANT" "$SCHEMA" "$BUILT" "${PARTS[@]}" <<'PY'
import json,sys
bid,name,checksum,schema,built,*parts=sys.argv[1:]
print(json.dumps({"id":bid,"name":name,"checksum":checksum,"schema":schema,"built":built,"parts":parts}))
PY
)"

if [[ "$DRY_RUN" == "1" ]]; then
  log "DRY_RUN=1 — в GitVerse ничего не заливаю. Запись о сборке:"
  echo "$NEW_BUILD"
  exit 0
fi

# --- 3. Прочитать текущий index.json (если есть) ------------------------------
log "Читаю текущий index.json..."
OLD_INDEX="$(wget -q -O - "$PKGBASE/index.json" 2>/dev/null || true)"

# посчитать новый индекс (новая сборка впереди, дедуп по id, держим KEEP),
# и СПИСОК ЧАСТЕЙ К УДАЛЕНИЮ (вытесненные сборки) -> в файл evict.txt
NEW_INDEX="$(python3 - "$KEEP" "$NEW_BUILD" "$WORKDIR/evict.txt" <<'PY'
import json,sys
keep=int(sys.argv[1]); new=json.loads(sys.argv[2]); evict_path=sys.argv[3]
old=sys.stdin.read().strip()
builds=[]
if old:
    try: builds=json.loads(old).get("builds",[])
    except Exception: builds=[]
builds=[b for b in builds if b.get("id")!=new["id"]]
allb=[new]+builds
keepb=allb[:keep]; evict=allb[keep:]
with open(evict_path,"w") as f:
    for b in evict:
        for p in b.get("parts",[]): f.write(p+"\n")
print(json.dumps({"builds":keepb},indent=2,ensure_ascii=False))
PY
<<<"$OLD_INDEX")"
printf '%s\n' "$NEW_INDEX" > "$WORKDIR/index.json"

# --- 4. Залить части текущей сборки --------------------------------------------
put() {  # put <localfile> <remotename>
  local f="$1" name="$2" code
  code="$(curl -sS "${AUTH[@]}" --upload-file "$f" "$PKGBASE/$name" -o /tmp/_gv_up -w '%{http_code}')"
  if [[ "$code" == "409" ]]; then
    curl -fsS "${AUTH[@]}" -X DELETE "$PKGBASE/$name" -o /dev/null 2>/dev/null || true
    code="$(curl -sS "${AUTH[@]}" --upload-file "$f" "$PKGBASE/$name" -o /tmp/_gv_up -w '%{http_code}')"
  fi
  [[ "$code" == "201" || "$code" == "200" ]] || { echo "Ошибка заливки $name (http=$code):" >&2; cat /tmp/_gv_up >&2; return 1; }
  log "  залит $name (http=$code)"
}

log "Заливаю части в реестр пакетов..."
for p in "${PARTS[@]}"; do put "$WORKDIR/$p" "$p"; done

# --- 5. Залить index.json ------------------------------------------------------
log "Заливаю index.json..."
put "$WORKDIR/index.json" "index.json"

# --- 6. Чистка: удалить части вытесненных сборок (держим KEEP) ------------------
if [[ -s "$WORKDIR/evict.txt" ]]; then
  log "Чищу старые сборки (оставляю $KEEP)..."
  while IFS= read -r old; do
    [[ -n "$old" ]] || continue
    curl -fsS "${AUTH[@]}" -X DELETE "$PKGBASE/$old" -o /dev/null 2>/dev/null \
      && log "  удалена часть $old" || log "  не удалось удалить $old (возможно, уже нет)"
  done < "$WORKDIR/evict.txt"
else
  log "Чистка: вытеснять нечего (сборок ≤ $KEEP)."
fi

# --- 7. Самопроверка -----------------------------------------------------------
log "Проверяю, что index.json отдаётся..."
wget -q -O /tmp/_gv_chk "$PKGBASE/index.json" && log "OK: $(tr -d '\n' </tmp/_gv_chk | cut -c1-90)..."

log "Готово! Зеркало GitVerse обновлено."
echo
echo "Части и index лежат под:"
echo "  $PKGBASE/"
echo "Клиент (grype-db-pull.sh) попробует GitHub, а если не выйдет — соберёт архив отсюда."
