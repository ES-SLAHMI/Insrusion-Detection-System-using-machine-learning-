import streamlit as st
import joblib 
import numpy as np
import pandas as pd
from scapy.all import sniff, IP
import threading

# Charger le modèle
model = joblib.load('modele_detection_cyberattaque.pkl')

# Titre Streamlit
st.markdown("<h1 style='text-align: center; color: #4CAF50;'>🔒 Détection de Cyberattaques</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>Analysez le trafic réseau et détectez les comportements malveillants grâce à l'IA.</p>", unsafe_allow_html=True)

# Choix du mode
mode = st.sidebar.selectbox("Choisissez le mode d'analyse", ["Temps réel (réseau)", "Importer un fichier CSV"])

# Liste pour stocker les paquets capturés
packets_batch = []

# Espace dynamique pour afficher les résultats
result_placeholder = st.empty()

# Initialisation de l'état
if 'result' not in st.session_state:
    st.session_state['result'] = "Aucune analyse encore."

# Fonction d'extraction des features
def extraire_features_batch(packets):
    features = np.zeros((1, 78))
    ip_packets = [pkt for pkt in packets if IP in pkt]
    if not ip_packets:
        return features

    first_src = ip_packets[0][IP].src

    fwd_lengths = [len(pkt) for pkt in ip_packets if pkt[IP].src == first_src]
    bwd_lengths = [len(pkt) for pkt in ip_packets if pkt[IP].dst == first_src]
    all_lengths = [len(pkt) for pkt in ip_packets]

    features[0, 0] = max(fwd_lengths) if fwd_lengths else 0
    features[0, 1] = min(fwd_lengths) if fwd_lengths else 0
    features[0, 2] = np.mean(fwd_lengths) if fwd_lengths else 0
    features[0, 3] = np.std(fwd_lengths) if fwd_lengths else 0
    features[0, 4] = sum(fwd_lengths) if fwd_lengths else 0
    features[0, 5] = np.var(all_lengths) if all_lengths else 0
    features[0, 6] = np.std(all_lengths) if all_lengths else 0
    features[0, 7] = np.mean(fwd_lengths) if fwd_lengths else 0

    fwd_times = [pkt.time for pkt in ip_packets if pkt[IP].src == first_src]
    fwd_iats = np.diff(fwd_times)
    features[0, 8] = max(fwd_iats) if len(fwd_iats) > 0 else 0
    features[0, 9] = min(fwd_iats) if len(fwd_iats) > 0 else 0
    features[0, 10] = np.std(fwd_iats) if len(fwd_iats) > 0 else 0

    features[0, 11] = 0
    features[0, 12] = 0
    features[0, 13] = len(fwd_lengths)
    features[0, 14] = sum(fwd_lengths) if fwd_lengths else 0
    features[0, 15] = len([pkt for pkt in ip_packets if pkt[IP].src == first_src and len(pkt) > 0])
    features[0, 16] = sum([pkt[IP].ihl * 4 for pkt in ip_packets]) if ip_packets else 0
    features[0, 17] = features[0, 16]
    features[0, 18] = np.mean(bwd_lengths) if bwd_lengths else 0

    for i in range(19, 78):
        features[0, i] = 0

    return features

# Fonction pour traiter un paquet et retourner une prédiction si nécessaire
def analyser_paquet(packet):
    global packets_batch
    packets_batch.append(packet)

    if len(packets_batch) >= 50:
        features = extraire_features_batch(packets_batch)
        prediction = model.predict(pd.DataFrame(features, columns=model.feature_names_in_))
        packets_batch.clear()
        return prediction[0]  # 1 = attaque, 0 = normal

# Lancer la capture réseau dans un thread
def lancer_capture():
    def traiter_paquet(pkt):
        pred = analyser_paquet(pkt)
        if pred is not None:
            if pred == 1:
                st.session_state['result'] = "🚨 Cyberattaque détectée !"
            else:
                st.session_state['result'] = "✅ Trafic normal détecté."
    sniff(prn=traiter_paquet, store=0)

import time

# Mode temps réel
if mode == "Temps réel (réseau)":
    st.info("Cliquez sur le bouton pour démarrer l’analyse du trafic réseau en temps réel.")

    if 'capture_active' not in st.session_state:
        st.session_state['capture_active'] = False

    def lancer_capture():
        def traiter_paquet(pkt):
            pred = analyser_paquet(pkt)
            if pred is not None:
                if pred == 1:
                    st.session_state['result'] = "🚨 Cyberattaque détectée !"
                else:
                    st.session_state['result'] = "✅ Trafic normal détecté."
        sniff(prn=traiter_paquet, store=0)

    if st.button("Démarrer la capture") and not st.session_state['capture_active']:
        st.session_state['capture_active'] = True
        st.success("✅ Capture en cours...")
        threading.Thread(target=lancer_capture, daemon=True).start()

    # Mise à jour automatique toutes les 1 seconde
    result_placeholder.write(st.session_state['result'])
    time.sleep(1)
    st.experimental_rerun()

# Mode fichier CSV
elif mode == "Importer un fichier CSV":
    fichier = st.file_uploader("Importer un fichier CSV contenant les données réseau", type=["csv"])
    if fichier is not None:
        data = pd.read_csv(fichier)
        st.write("Aperçu des données :", data.head())

        if data.shape[1] != 78:
            st.error(f"🚫 Erreur : Le fichier CSV doit contenir 78 colonnes, trouvé {data.shape[1]} colonnes.")
        else:
            if st.button("Analyser le fichier"):
                try:
                    predictions = model.predict(data.values)
                    data['Prédiction'] = predictions
                    st.write(data)

                    attaques = (predictions == 1).sum()
                    normaux = (predictions == 0).sum()
                    st.success(f"✅ Résultats : {normaux} normaux, 🚨 {attaques} attaques détectées.")
                except Exception as e:
                    st.error(f"🚫 Erreur lors de la prédiction : {e}")
