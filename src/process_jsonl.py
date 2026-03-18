import pandas as pd
import json
import re
from pathlib import Path

# ══════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════

DATA_ROOT = Path('cleaned_data')
OUTPUT_FILE = Path('darkgram_cti_final.jsonl')

# Table 1 : Posts (30 champs utiles, sans "channel id")
POST_META_SCHEMA = [
    'url', 'date', 'views', 'forwards', 'replies',
    'reactions', 'out', 'mentioned', 'media_unread',
    'silent', 'post', 'from_scheduled', 'legacy',
    'edit_hide', 'pinned', 'noforwards', 'peer_channel',
    'from_id_user',
    'fwd_from',             
    'via_bot_id',
    'reply_to_msg_id', 'reply_to_scheduled', 'forum_topic',
    'media_photo_id', 'reply_markup', 'edit_date',
    'post_author', 'grouped_id',
    'restriction_reason',    
    'ttl_period'
]

# Table 2 : Replies et Recovered (5 champs utiles)
REPLY_META_SCHEMA = [
    'url', 'date', 'views', 'forwards', 'reactions'
]


# ══════════════════════════════════════════════
# UTILITAIRES
# ══════════════════════════════════════════════

def clean_val(val):
    if pd.isna(val):
        return None
    if hasattr(val, 'item'):
        return val.item()
    return val


def id_to_str(val):
    if pd.isna(val):
        return ""
    try:
        return str(int(float(val)))
    except (ValueError, TypeError):
        return str(val).strip()


def safe_content(val):
    if pd.isna(val):
        return ""
    s = str(val).strip()
    if s.lower() in ('nan', 'none', 'null'):
        return ""
    return s


def extract_post_id_from_filename(filename):
    stem = filename.replace("_replies.csv", "")
    match = re.search(r'_(\d+)$', stem)
    if match:
        return match.group(1)
    for part in reversed(stem.split("_")):
        if part.isdigit():
            return part
    return None


# ══════════════════════════════════════════════
# CONSTRUCTION DES DOCUMENTS
# ══════════════════════════════════════════════
def build_post_text(post_id, channel, content):
    return (
        f"[POST_ID: {post_id}] | "
        f"TYPE: POST | "
        f"CHANNEL: {channel} | "
        f"CONTENT: {content}"
    )


def build_reply_text(parent_id, reply_id, channel, content):
    return (
        f"[PARENT_POST_ID: {parent_id}] | "
        f"[REPLY_ID: {reply_id}] | "
        f"TYPE: REPLY | "
        f"CHANNEL: {channel} | "
        f"CONTENT: {content}"
    )


def build_metadata(row, schema, extras):
    meta = {}
    for field in schema:
        meta[field] = clean_val(row.get(field))
    meta.update(extras)
    return meta


# ══════════════════════════════════════════════
# PIPELINE
# ══════════════════════════════════════════════

def process_to_jsonl():
    counters = {
        'posts': 0, 'replies': 0,
        'recovered': 0, 'skipped': 0
    }

    if not DATA_ROOT.exists():
        print(f"❌ Dossier introuvable : {DATA_ROOT}")
        return

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f_out:

        for category_dir in sorted(DATA_ROOT.iterdir()):
            if not category_dir.is_dir():
                continue
            category = category_dir.name

            for channel_dir in sorted(category_dir.iterdir()):
                if not channel_dir.is_dir():
                    continue

                channel_name = channel_dir.name
                posts_csv = channel_dir / f"{channel_name}.csv"
                replies_folder = (
                    channel_dir / f"{channel_name}_replies"
                )
                processed_ids = set()

                # ─── PHASE 1 : POSTS (Table 1) ───
                if posts_csv.exists():
                    try:
                        df = pd.read_csv(
                            posts_csv, low_memory=False
                        )
                        df.rename(
                            columns=lambda x: x.strip().lower(),
                            inplace=True
                        )

                        for _, row in df.iterrows():
                            p_id = id_to_str(
                                row.get('post id')
                                or row.get('id')
                            )
                            if not p_id:
                                counters['skipped'] += 1
                                continue

                            content = safe_content(
                                row.get('message')
                            )
                            text = build_post_text(
                                post_id=p_id,
                                channel=channel_name,
                                content=content,
                            )
                            metadata = build_metadata(
                                row=row,
                                schema=POST_META_SCHEMA,
                                extras={
                                    "category": category,
                                    "doc_type": "original_post",
                                    "channel_name": channel_name,
                                    "recovered": False,
                                }
                            )

                            f_out.write(json.dumps(
                                {"text": text,
                                 "metadata": metadata},
                                ensure_ascii=False
                            ) + '\n')
                            processed_ids.add(p_id)
                            counters['posts'] += 1

                    except Exception as e:
                        print(
                            f"  ⚠️ Erreur Posts"
                            f" [{channel_name}]: {e}"
                        )

                # ─── PHASE 2 : REPLIES & RECOVERY ───
                if replies_folder.exists():
                    for rf in sorted(replies_folder.iterdir()):
                        if not rf.name.endswith("_replies.csv"):
                            continue

                        parent_id = (
                            extract_post_id_from_filename(rf.name)
                        )
                        if not parent_id:
                            continue

                        try:
                            df_rep = pd.read_csv(
                                rf, low_memory=False
                            )
                            df_rep.rename(
                                columns=lambda x: x.strip().lower(),
                                inplace=True
                            )
                            if df_rep.empty:
                                continue

                            # AUTO-RECOVERY
                            if parent_id not in processed_ids:
                                row0 = df_rep.iloc[0]
                                content = safe_content(
                                    row0.get('message')
                                )
                                text_rec = build_post_text(
                                    post_id=parent_id,
                                    channel=channel_name,
                                    content=content,
                                )
                                meta_rec = build_metadata(
                                    row=row0,
                                    schema=REPLY_META_SCHEMA,
                                    extras={
                                        "category": category,
                                        "doc_type":
                                            "original_post",
                                        "channel_name":
                                            channel_name,
                                        "recovered": True,
                                    }
                                )
                                f_out.write(json.dumps(
                                    {"text": text_rec,
                                     "metadata": meta_rec},
                                    ensure_ascii=False
                                ) + '\n')
                                processed_ids.add(parent_id)
                                counters['recovered'] += 1
                                counters['posts'] += 1

                            # REPLIES
                            for _, rep in (
                                df_rep.iloc[1:].iterrows()
                            ):
                                r_id = id_to_str(
                                    rep.get('id')
                                )
                                content = safe_content(
                                    rep.get('message')
                                )
                                if not content and not r_id:
                                    counters['skipped'] += 1
                                    continue

                                text_r = build_reply_text(
                                    parent_id=parent_id,
                                    reply_id=r_id,
                                    channel=channel_name,
                                    content=content,
                                )
                                meta_r = build_metadata(
                                    row=rep,
                                    schema=REPLY_META_SCHEMA,
                                    extras={
                                        "category": category,
                                        "doc_type": "reply",
                                        "parent_post_id":
                                            parent_id,
                                        "channel_name":
                                            channel_name,
                                    }
                                )
                                f_out.write(json.dumps(
                                    {"text": text_r,
                                     "metadata": meta_r},
                                    ensure_ascii=False
                                ) + '\n')
                                counters['replies'] += 1

                        except Exception as e:
                            print(
                                f"  ⚠️ Erreur"
                                f" {rf.name}: {e}"
                            )

    # ─── RAPPORT ───
    total = counters['posts'] + counters['replies']
    print(f"\n{'═'*50}")
    print(f"  ✅ FUSION TERMINÉE")
    print(f"{'═'*50}")
    print(f"  📄 Output          : {OUTPUT_FILE}")
    print(f"  📊 Posts            : {counters['posts']}")
    print(f"     ├─ Depuis CSV    : "
          f"{counters['posts'] - counters['recovered']}")
    print(f"     └─ Recovered     : {counters['recovered']}")
    print(f"  💬 Replies          : {counters['replies']}")
    print(f"  📦 Total            : {total}")
    print(f"  ⏭️  Skipped         : {counters['skipped']}")
    print(f"{'═'*50}\n")


if __name__ == "__main__":
    process_to_jsonl()