#!/usr/bin/env bash
#
# github-grype-mirror.sh
# Зеркалит официальную grype v6 vulnerability-db в GitHub:
#   - архив базы  -> ассет релиза (лимит 2 ГБ, наши 123 МБ влезают)
#   - latest.json -> файл в репозитории, отдаётся через raw.githubusercontent.com
#
# grype:
#   db:
#     update-url: "https://raw.githubusercontent.com/<owner>/<repo>/<branch>/databases"
#   (grype сам допишет /v6/latest.json)
#
set -euo pipefail

# ----------------------------- НАСТРОЙКИ -------------------------------------
#GH_OWNER="${GH_OWNER:?set GH_OWNER (логин/организация на GitHub)}"
GH_OWNER=purringfish
#GH_REPO="${GH_REPO:?set GH_REPO (репозиторий-зеркало)}"
GH_REPO=grype-mirror-lol
#GH_BRANCH="${GH_BRANCH:-main}"
GH_BRANCH=main
# Токен в скрипте НЕ хранится — берётся только из окружения.
# В GitHub Actions сюда подставляется secrets.GITHUB_TOKEN (см. .github/workflows/mirror.yml).
# Для локального запуска: TOKEN=ghp_xxx ./github-grype-mirror.sh
TOKEN="${TOKEN:?нужен TOKEN в окружении (в CI это secrets.GITHUB_TOKEN)}"

UPSTREAM="https://grype.anchore.io/databases/v6"
API="https://api.github.com"
UPLOADS="https://uploads.github.com"
WORKDIR="$(mktemp -d)"
DRY_RUN="${DRY_RUN:-0}"
# -----------------------------------------------------------------------------

trap 'rm -rf "$WORKDIR"' EXIT

HDR=(-H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28")

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
jget() { python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('$1','') if isinstance(d,dict) else '')"; }

# --- 1. Скачать манифест и архив с anchore -----------------------------------
log "Качаю официальный latest.json..."
curl -fsSL "$UPSTREAM/latest.json" -o "$WORKDIR/upstream.json"

read -r ARCHIVE_PATH CHECKSUM BUILT SCHEMA < <(python3 - "$WORKDIR/upstream.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(d["path"],d["checksum"],d["built"],d["schemaVersion"])
PY
)
ARCHIVE_NAME="$(basename "$ARCHIVE_PATH")"
ASSET_NAME="${ARCHIVE_NAME//:/.}"            # GitHub не любит ':' в имени ассета
log "Версия: $SCHEMA | сборка: $BUILT"
log "Архив: $ARCHIVE_NAME  (ассет: $ASSET_NAME)"

log "Качаю архив базы (~123 МБ)..."
curl -fSL "$UPSTREAM/$ARCHIVE_PATH" -o "$WORKDIR/$ASSET_NAME"

log "Проверяю sha256..."
WANT="${CHECKSUM#sha256:}"
GOT="$(sha256sum "$WORKDIR/$ASSET_NAME" | awk '{print $1}')"
[[ "$WANT" == "$GOT" ]] || { echo "sha256 не совпала! want=$WANT got=$GOT" >&2; exit 1; }
log "sha256 ОК | размер: $(du -h "$WORKDIR/$ASSET_NAME" | awk '{print $1}')"

if [[ "$DRY_RUN" == "1" ]]; then
  log "DRY_RUN=1 — на GitHub ничего не заливаю."
  exit 0
fi

TAG="$SCHEMA"   # например v6.1.7

# --- 2. Создать или найти релиз по тегу --------------------------------------
log "Ищу/создаю релиз $TAG..."
REL="$(curl -s "${HDR[@]}" "$API/repos/$GH_OWNER/$GH_REPO/releases/tags/$TAG")"
REL_ID="$(jget id <<<"$REL")"
if [[ -z "$REL_ID" || "$REL_ID" == "None" ]]; then
  REL="$(curl -s "${HDR[@]}" -X POST "$API/repos/$GH_OWNER/$GH_REPO/releases" \
    -d "$(python3 -c 'import json,sys;print(json.dumps({"tag_name":sys.argv[1],"name":"grype db "+sys.argv[1],"target_commitish":sys.argv[2],"body":"Mirror of "+sys.argv[3]}))' "$TAG" "$GH_BRANCH" "$ARCHIVE_NAME")")"
  REL_ID="$(jget id <<<"$REL")"
fi
[[ -n "$REL_ID" && "$REL_ID" != "None" ]] || { echo "Не удалось создать/найти релиз. Ответ:" >&2; echo "$REL" | head -c 400 >&2; exit 1; }
log "release_id = $REL_ID"

# --- 3. Удалить старый ассет с тем же именем (если есть) ----------------------
OLD_ASSET_ID="$(curl -s "${HDR[@]}" "$API/repos/$GH_OWNER/$GH_REPO/releases/$REL_ID/assets" \
  | python3 -c "import json,sys
for a in json.load(sys.stdin):
    if a.get('name')=='$ASSET_NAME': print(a['id']); break" 2>/dev/null || true)"
if [[ -n "$OLD_ASSET_ID" ]]; then
  log "удаляю старый ассет id=$OLD_ASSET_ID"
  curl -s "${HDR[@]}" -X DELETE "$API/repos/$GH_OWNER/$GH_REPO/releases/assets/$OLD_ASSET_ID" -o /dev/null
fi

# --- 4. Загрузить архив ассетом ----------------------------------------------
log "Загружаю архив ассетом..."
ATT="$(curl -sS "${HDR[@]}" -H "Content-Type: application/octet-stream" \
  --data-binary @"$WORKDIR/$ASSET_NAME" \
  "$UPLOADS/repos/$GH_OWNER/$GH_REPO/releases/$REL_ID/assets?name=$ASSET_NAME")"
DL_URL="$(jget browser_download_url <<<"$ATT")"
[[ -n "$DL_URL" && "$DL_URL" != "None" ]] || { echo "Ошибка загрузки ассета. Ответ:" >&2; echo "$ATT" | head -c 400 >&2; exit 1; }
log "URL ассета: $DL_URL"

# --- 5. Собрать latest.json и закоммитить в databases/v6/latest.json ----------
python3 - "$WORKDIR/upstream.json" "$DL_URL" > "$WORKDIR/latest.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d["path"]=sys.argv[2]
print(json.dumps(d,indent=2,ensure_ascii=False))
PY
B64="$(base64 -w0 < "$WORKDIR/latest.json" 2>/dev/null || base64 < "$WORKDIR/latest.json" | tr -d '\n')"
GPATH="databases/v6/latest.json"
SHA="$(curl -s "${HDR[@]}" "$API/repos/$GH_OWNER/$GH_REPO/contents/$GPATH?ref=$GH_BRANCH" | jget sha)"
BODY="$(python3 -c 'import json,sys
o={"message":"grype db "+sys.argv[1],"content":sys.argv[2],"branch":sys.argv[3]}
if sys.argv[4] and sys.argv[4]!="None": o["sha"]=sys.argv[4]
print(json.dumps(o))' "$TAG" "$B64" "$GH_BRANCH" "$SHA")"
log "Коммичу $GPATH..."
RESP="$(curl -sS "${HDR[@]}" -X PUT "$API/repos/$GH_OWNER/$GH_REPO/contents/$GPATH" -d "$BODY")"
python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get("content") else 1)' <<<"$RESP" \
  || { echo "Ошибка коммита latest.json:" >&2; echo "$RESP" | head -c 400 >&2; exit 1; }

# --- 6. Чистка: в релизе всегда только актуальный архив ----------------------
# Все сборки одной схемы (v6.1.7) лежат ассетами в ОДНОМ релизе. Оставляем 1
# самый свежий ассет, остальные удаляем, чтобы зеркало не разрасталось.
KEEP=1
log "Чищу старые архивы в релизе (оставляю только $KEEP последний)..."
(
  curl -s "${HDR[@]}" "$API/repos/$GH_OWNER/$GH_REPO/releases/$REL_ID/assets?per_page=100" \
    | KEEP="$KEEP" python3 -c "import json,sys,os
k=int(os.environ['KEEP'])
a=[x for x in json.load(sys.stdin) if isinstance(x,dict)]
a.sort(key=lambda x:x.get('created_at',''),reverse=True)
for x in a[k:]:
    print(x['id'], x.get('name',''))" \
    | while read -r AID ANAME; do
        [[ -n "$AID" ]] || continue
        log "  удаляю ассет id=$AID $ANAME"
        curl -s "${HDR[@]}" -X DELETE "$API/repos/$GH_OWNER/$GH_REPO/releases/assets/$AID" -o /dev/null
      done
) || log "чистку пропустил (не критично)"

UPDATE_URL="https://raw.githubusercontent.com/$GH_OWNER/$GH_REPO/$GH_BRANCH/databases"
log "Готово!"
echo
echo "Настрой grype:"
echo "  db:"
echo "    update-url: \"$UPDATE_URL\""
echo
echo "Проверка:"
echo "  GRYPE_DB_UPDATE_URL=$UPDATE_URL grype db update -vv"
