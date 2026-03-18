import pandas as pd
import json
import os

# --- CONFIGURATION ---
DATA_ROOT = 'cleaned_data' 
OUTPUT_FILE = 'darkgram_cti_final_granular.jsonl'

def clean_val(val):
    """Transforme les NaN de Pandas en None pour un JSON valide."""
    return None if pd.isna(val) else val

def process_to_jsonl():
    total_docs = 0
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f_out:
        # 1. Parcourir les catégories
        for category in os.listdir(DATA_ROOT):
            cat_path = os.path.join(DATA_ROOT, category)
            if not os.path.isdir(cat_path): continue

            # 2. Parcourir les canaux
            for channel_name in os.listdir(cat_path):
                channel_path = os.path.join(cat_path, channel_name)
                posts_csv = os.path.join(channel_path, f"{channel_name}.csv")
                replies_folder = os.path.join(channel_path, f"{channel_name}_replies")
                processed_ids = set()
                if not os.path.exists(posts_csv): continue
                # --- PHASE 1 : LECTURE DU CSV DES POSTS ---
                if os.path.exists(posts_csv):  
                  # --- CHARGEMENT ET NORMALISATION DES POSTS ---
                  df_posts = pd.read_csv(posts_csv, low_memory=False)
                  # ON NE CHANGE QUE LES NOMS DES CLÉS ICI (en minuscules et sans espaces) POUR FACILITER L'EXTRACTION DES MÉTADONNÉES
                  df_posts.rename(columns=lambda x: x.strip().lower(), inplace=True)

                  # --- CRÉATION DU DOCUMENT POST ---
                  for _, post in df_posts.iterrows():
                      # Préparation des variables locales pour plus de clarté
                      p_id = id_to_str(post.get('post id'))
                      
                      # Construction du texte multi-ligne pour le LLM
                      text_formatted = f"""
                        POST_ID: {p_id}
                        TYPE: MAIN_POST
                        CHANNEL: {channel_name}
                        CONTENT:
                        {post.get('message', '')}
                        DATE: {post.get('date', 'Unknown')}
                        FORWARDED_FROM: {clean_val(post.get('fwd_from'))}
                        RESTRICTION_REASON: {clean_val(post.get('restriction_reason'))}
                        REACTIONS: {clean_val(post.get('reactions'))}
                        """
                      metadata_formatted = {
                          # Infos système
                          "category": category,
                          "doc_type": "original_post",
                          # Identifiants
                          "channel_id": clean_val(post.get('channel id')),
                          "post_id": p_id,
                          "from_user_id": clean_val(post.get('from_id_user')),
                          "via_bot_id": clean_val(post.get('via_bot_id')),
                          "media_photo_id": clean_val(post.get('media_photo_id')),
                          "grouped_id": clean_val(post.get('grouped_id')),
                          "reply_to_msg_id": clean_val(post.get('reply_to_msg_id')),
                          # Dates
                          "edit_date": clean_val(post.get('edit_date')),
                          # Métriques
                          "views": clean_val(post.get('views')),
                          "forwards": clean_val(post.get('forwards')),
                          "replies": clean_val(post.get('replies')),
                          "ttl_period": clean_val(post.get('ttl_period')),
                          # Flags techniques
                          "out": clean_val(post.get('out')),
                          "mentioned": clean_val(post.get('mentioned')),
                          "media_unread": clean_val(post.get('media_unread')),
                          "silent": clean_val(post.get('silent')),
                          "post_flag": clean_val(post.get('post')), # renommé post_flag pour éviter confusion
                          "from_scheduled": clean_val(post.get('from_scheduled')),
                          "legacy": clean_val(post.get('legacy')),
                          "edit_hide": clean_val(post.get('edit_hide')),
                          "pinned": clean_val(post.get('pinned')),
                          "no_forwards": clean_val(post.get('noforwards')),
                          "reply_to_scheduled": clean_val(post.get('reply_to_scheduled')),
                          "forum_topic": clean_val(post.get('forum_topic')),
                          "url": clean_val(post.get('url')),
                      }

                      # Création de l'unité finale
                      post_doc = {
                          "text": text_formatted.strip(), # strip() pour enlever les sauts de ligne inutiles au début/fin
                          "metadata": metadata_formatted
                      }
                      f_out.write(json.dumps(post_doc) + '\n')
                      processed_ids.add(p_id)
                      total_posts += 1
                      
                  

                  # --- PHASE 2 : RÉCUPÉRATION DANS LE DOSSIER REPLIES ---
                  if os.path.exists(replies_folder):
                        pattern = f"_{p_id}_replies.csv"
                        for f_rep in os.listdir(replies_folder):
                            if f_rep.endswith(pattern):
                                try:
                                    df_rep = pd.read_csv(os.path.join(replies_folder, f_rep), low_memory=False)
                                    #  (en minuscules et sans espaces) POUR FACILITER L'EXTRACTION DES MÉTADONNÉES
                                    df_rep.rename(columns=lambda x: x.strip().lower(), inplace=True)
                                    # --- À l'intérieur de la boucle qui traite les réponses (df_rep.iloc[1:]) ---
                                    for _, rep in df_rep.iloc[1:].iterrows():
                                            r_id = id_to_str(rep.get('id'))
                                            r_date = str(rep.get('date', 'Unknown'))

                                            # 1. Structure du texte pour le LLM (RAG)
                                            # On ajoute le PARENT_POST_ID au début pour la traçabilité sémantique
                                            text_reply_formatted = (
                                                f"[PARENT_POST_ID: {p_id}] [REPLY_ID: {r_id}] TYPE: REPLY | "
                                                f"CHANNEL: {channel_name} | "
                                                f"CONTENT: {rep.get('message', '')} | "
                                                f"DATE: {r_date}"
                                            )

                                            # 2. Structure des métadonnées pour les filtres des Agents
                                            metadata_reply_formatted = {
                                                # Infos système indispensables
                                                "category": category,
                                                "doc_type": "reply",
                                                # Identifiants
                                                "reply_id": r_id,
                                                "channel_id": clean_val(rep.get('channel id')),
                                                "parent_post_id": p_id,
                                                "url": clean_val(rep.get('url')),
                                                # Métriques
                                                "views": clean_val(rep.get('views')),
                                                "forwards": clean_val(rep.get('forwards')),
                                                "reactions": clean_val(rep.get('reactions')),

                                                # Date brute pour filtrage
                                                "date": r_date,
                                                
                                            }

                                            reply_unit = {
                                                "text": text_reply_formatted,
                                                "metadata": metadata_reply_formatted
                                            }

                                            f_out.write(json.dumps(reply_unit) + '\n')
                                            total_replies += 1
                            if p_id not in processed_ids and p_id != "":
                                text_rec = f"""
                                  POST_ID: {p_id}
                                  TYPE: MAIN_POST (RECOVERED)
                                  CHANNEL: {channel_name}
                                  CONTENT:
                                  {row_zero.get('message', '')}
                                  DATE: {row_zero.get('date', 'Unknown')}
                                  REACTIONS: {clean_val(row_zero.get('reactions'))}
                                  """
                                meta_rec = {col: clean_val(row_zero.get(col)) for col in df_rep.columns}
                                meta_rec.update({"category": category, "doc_type": "original_post", "recovered": True, "post id": p_id_parent})
                                
                                f_out.write(json.dumps({"text": text_rec.strip(), "metadata": meta_rec}) + '\n')
                                processed_ids.add(p_id_parent)
                                total_recovered += 1
                                total_posts += 1            
                      except Exception as e:
                          print(f"⚠️ Erreur sur reply {f_rep}: {e}")
                          break

    print(f"✅ Opération réussie : {total_docs} documents créés.")

if __name__ == "__main__":
    process_to_jsonl()