import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import pandas as pd
import joblib
import numpy as np
from scapy.all import sniff, IP
import threading

# Charger le modèle
model = joblib.load('modele_detection_cyberattaque.pkl')

# Liste pour stocker les paquets
packets_batch = []

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

# Fonction pour analyser un paquet
def analyser_paquet(packet, text_widget):
    global packets_batch
    packets_batch.append(packet)

    if len(packets_batch) >= 50:
        features = extraire_features_batch(packets_batch)
        prediction = model.predict(pd.DataFrame(features, columns=model.feature_names_in_))
        packets_batch.clear()

        if prediction[0] == 1:
            text_widget.insert(tk.END, "🚨 Cyberattaque détectée !\n")
        else:
            text_widget.insert(tk.END, "✅ Trafic normal détecté.\n")
        text_widget.see(tk.END)

# Fonction pour lancer la capture réseau
def lancer_capture(text_widget):
    def traiter(pkt):
        analyser_paquet(pkt, text_widget)
    sniff(prn=traiter, store=0)

# Fonction pour importer et analyser un CSV
def importer_csv(text_widget):
    fichier = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if fichier:
        try:
            data = pd.read_csv(fichier)
            if data.shape[1] != 78:
                messagebox.showerror("Erreur", f"Le fichier doit contenir 78 colonnes, trouvé {data.shape[1]}.")
                return

            predictions = model.predict(data.values)
            attaques = (predictions == 1).sum()
            normaux = (predictions == 0).sum()

            text_widget.insert(tk.END, f"Analyse terminée : {normaux} normaux, 🚨 {attaques} attaques détectées.\n")
            text_widget.see(tk.END)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

# Interface graphique
fenetre = tk.Tk()
fenetre.title("Détection de Cyberattaques")
fenetre.geometry("600x400")

label = tk.Label(fenetre, text="Détection de Cyberattaques", font=("Arial", 16), fg="#4CAF50")
label.pack(pady=10)

text_area = scrolledtext.ScrolledText(fenetre, width=70, height=15)
text_area.pack(pady=10)

bouton_capture = tk.Button(fenetre, text="Démarrer Capture Réseau", command=lambda: threading.Thread(target=lancer_capture, args=(text_area,), daemon=True).start())
bouton_capture.pack(pady=5)

bouton_csv = tk.Button(fenetre, text="Analyser un fichier CSV", command=lambda: importer_csv(text_area))
bouton_csv.pack(pady=5)

fenetre.mainloop()
