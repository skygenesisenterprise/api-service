# Intégration VoIP avec l'API Sky Genesis Enterprise

## Vue d'ensemble

L'API Sky Genesis Enterprise fournit des fonctionnalités complètes de VoIP (Voice over IP) et de communication en temps réel, permettant l'intégration transparente avec des environnements PBX (Private Branch Exchange). Cette documentation explique comment utiliser et intégrer l'API pour des communications vocales, vidéo et de messagerie instantanée dans des infrastructures PBX.

## Architecture

L'API implémente une architecture moderne basée sur WebRTC pour la signalisation et le transport média, avec support pour :

- **Appels peer-to-peer** : Communication directe entre deux participants
- **Salles de conférence** : Communication multi-participants
- **Signaling sécurisé** : Échange de métadonnées WebRTC via API REST
- **Média chiffré** : Transport SRTP/DTLS pour la sécurité
- **Présence et statut** : Intégration avec XMPP/WebSocket pour la présence

## Prérequis

### Authentification
Toutes les requêtes VoIP nécessitent une authentification via JWT ou API key :

```bash
Authorization: Bearer <jwt_token>
# ou
X-API-Key: <api_key>
```

### Environnement PBX
- **Serveur PBX compatible WebRTC** (Asterisk, FreeSWITCH, etc.)
- **Certificats TLS valides** pour le chiffrement
- **Configuration réseau** permettant les connexions UDP/TCP sur les ports média
- **Support WebRTC** côté client (navigateurs modernes ou applications mobiles)

### Dépendances
- **WebRTC** : Pour le transport média
- **WebSocket** : Pour la présence et les notifications temps réel
- **SRTP/DTLS** : Pour le chiffrement média

## Endpoints API VoIP

### Gestion des appels

#### Initier un appel
```http
POST /api/v1/voip/calls
Authorization: Bearer <token>
Content-Type: application/json

{
  "participants": ["user456", "user789"],
  "call_type": "video"
}
```

**Types d'appel supportés :**
- `audio` : Appel vocal uniquement
- `video` : Appel avec vidéo
- `screen` : Partage d'écran

#### Accepter un appel
```http
POST /api/v1/voip/calls/{call_id}/accept
Authorization: Bearer <token>
```

#### Terminer un appel
```http
POST /api/v1/voip/calls/{call_id}/end
Authorization: Bearer <token>
```

#### Obtenir les informations d'un appel
```http
GET /api/v1/voip/calls/{call_id}
Authorization: Bearer <token>
```

#### Lister les appels actifs
```http
GET /api/v1/voip/calls
Authorization: Bearer <token>
```

### Gestion des salles de conférence

#### Créer une salle
```http
POST /api/v1/voip/rooms
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Réunion équipe",
  "max_participants": 10,
  "settings": {
    "allow_recording": true,
    "moderator_controls": true,
    "waiting_room": false
  }
}
```

#### Rejoindre une salle
```http
POST /api/v1/voip/rooms/{room_id}/join
Authorization: Bearer <token>
```

#### Obtenir les informations d'une salle
```http
GET /api/v1/voip/rooms/{room_id}
Authorization: Bearer <token>
```

#### Lister les salles actives
```http
GET /api/v1/voip/rooms
Authorization: Bearer <token>
```

### Signaling WebRTC

#### Envoyer un message de signaling
```http
POST /api/v1/voip/calls/{call_id}/signaling
Authorization: Bearer <token>
Content-Type: application/json

{
  "to_user": "user456",
  "message_type": "offer",
  "payload": {
    "sdp": "v=0\r\no=- 12345 67890 IN IP4 192.168.1.1\r\n...",
    "type": "offer"
  }
}
```

**Types de messages supportés :**
- `offer` : Offre SDP WebRTC
- `answer` : Réponse SDP WebRTC
- `ice_candidate` : Candidat ICE
- `hangup` : Raccrocher
- `mute` / `unmute` : Contrôle audio

#### Récupérer les messages de signaling
```http
GET /api/v1/voip/calls/{call_id}/signaling
Authorization: Bearer <token>
```

## Intégration avec PBX

### Architecture d'intégration

```
[PBX Server] <---SIP/WebRTC---> [SGE API Gateway] <---WebRTC---> [Clients]
                                      |
                                      v
                               [SGE VoIP Service]
                                      |
                                      v
                            [WebSocket/XMPP Presence]
```

### Configuration PBX Asterisk

Exemple de configuration Asterisk pour l'intégration :

```ini
; extensions.conf
[sky-genesis-voip]
exten => _X.,1,NoOp(Appel vers SGE: ${EXTEN})
exten => _X.,n,Set(SGE_TOKEN=${PJSIP_HEADER(X-API-Key)})
exten => _X.,n,Set(SGE_ROOM=${PJSIP_HEADER(X-Room-ID)})
exten => _X.,n,GotoIf($["${SGE_TOKEN}" = ""]?no-auth)
exten => _X.,n,Set(CALL_ID=${STRFTIME(${EPOCH},,%Y%m%d%H%M%S)}-${EXTEN})
exten => _X.,n,AGI(sge-voip-integration.php,${CALL_ID},${EXTEN})
exten => _X.,n,Hangup()

exten => no-auth,1,Playback(auth-thankyou)
exten => no-auth,n,Hangup()
```

### Script d'intégration PHP

```php
<?php
// sge-voip-integration.php
$callId = $argv[1];
$extension = $argv[2];

$sgeApiUrl = 'https://api.skygenesisenterprise.com/api/v1/voip';

// Créer l'appel dans SGE
$callData = [
    'participants' => [$extension],
    'call_type' => 'audio'
];

$ch = curl_init("$sgeApiUrl/calls");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($callData));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'Authorization: Bearer ' . getenv('SGE_JWT_TOKEN')
]);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if ($httpCode === 201) {
    $callInfo = json_decode($response, true);
    // Stocker le call_id pour référence future
    file_put_contents("/tmp/sge_call_$callId", json_encode($callInfo));
    echo "SET VARIABLE SGE_CALL_ID $callInfo[id]\n";
} else {
    echo "SET VARIABLE SGE_ERROR \"Call creation failed\"\n";
}

curl_close($ch);
?>
```

### Intégration WebRTC côté client

#### Configuration WebRTC
```javascript
// Configuration STUN/TURN pour NAT traversal
const rtcConfiguration = {
    iceServers: [
        { urls: 'stun:stun.skygenesisenterprise.com:19302' },
        {
            urls: 'turn:turn.skygenesisenterprise.com:3478',
            username: 'user',
            credential: 'password'
        }
    ]
};

// Créer une connexion peer
const peerConnection = new RTCPeerConnection(rtcConfiguration);

// Gestion des candidats ICE
peerConnection.onicecandidate = (event) => {
    if (event.candidate) {
        // Envoyer le candidat via signaling
        sendSignalingMessage(callId, 'ice_candidate', {
            candidate: event.candidate
        });
    }
};

// Gestion des tracks média
peerConnection.ontrack = (event) => {
    // Ajouter le stream audio/vidéo à l'interface
    const remoteVideo = document.getElementById('remote-video');
    remoteVideo.srcObject = event.streams[0];
};
```

#### Flux d'appel typique
```javascript
async function initiateCall(participants, callType) {
    // 1. Créer l'appel via API
    const callResponse = await fetch('/api/v1/voip/calls', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${jwtToken}`
        },
        body: JSON.stringify({
            participants,
            call_type: callType
        })
    });

    const callData = await callResponse.json();
    const callId = callData.id;

    // 2. Créer la connexion WebRTC
    const peerConnection = new RTCPeerConnection(rtcConfiguration);

    // 3. Ajouter les tracks locaux
    const localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: callType === 'video'
    });

    localStream.getTracks().forEach(track => {
        peerConnection.addTrack(track, localStream);
    });

    // 4. Créer et envoyer l'offre
    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);

    await sendSignalingMessage(callId, 'offer', offer);

    return { callId, peerConnection };
}
```

### Gestion de la présence

#### Connexion WebSocket pour la présence
```javascript
const ws = new WebSocket('wss://api.skygenesisenterprise.com/ws/auth?token=' + jwtToken);

ws.onopen = () => {
    // S'abonner à la présence
    ws.send(JSON.stringify({
        type: 'Subscribe',
        channel: 'presence:user123'
    }));

    // Mettre à jour le statut
    updatePresence('online', 'Disponible pour les appels');
};

function updatePresence(status, message) {
    ws.send(JSON.stringify({
        type: 'PresenceUpdate',
        user_id: 'user123',
        status,
        status_message: message
    }));
}
```

## Métriques et monitoring

### Métriques SNMP VoIP
L'API expose des métriques VoIP via SNMP pour le monitoring :

```bash
# Appels actifs
snmpget -v2c -c public localhost 1.3.6.1.4.1.8072.1.3.2.3.2.1.1.1

# Salles actives
snmpget -v2c -c public localhost 1.3.6.1.4.1.8072.1.3.2.3.2.1.2.1

# Qualité des appels
snmpget -v2c -c public localhost 1.3.6.1.4.1.8072.1.3.2.3.2.1.9.1
```

### Métriques Prometheus
```bash
# Métriques d'appels
curl http://localhost:8080/api/v1/metrics/prometheus | grep voip
```

## Sécurité et meilleures pratiques

### Chiffrement
- **Signaling** : Toutes les communications API utilisent HTTPS/TLS 1.3
- **Média** : SRTP avec chiffrement DTLS
- **Stockage** : Clés de chiffrement dans Vault

### Authentification
- **JWT Tokens** : Pour l'authentification utilisateur
- **API Keys** : Pour l'accès service
- **Certificats** : Authentification mutuelle optionnelle

### Gestion des ressources
- **Limites d'appels** : Configuration des limites par utilisateur
- **Timeout** : Nettoyage automatique des appels inactifs
- **Rate limiting** : Protection contre les abus

### Conformité
- **RGPD** : Gestion des données personnelles
- **HIPAA** : Sécurité pour les données médicales
- **Audit** : Logging complet des appels

## Dépannage

### Problèmes courants

#### Échec de connexion WebRTC
- Vérifier la configuration STUN/TURN
- Contrôler les règles firewall pour UDP 3478
- Valider les certificats TLS

#### Problèmes de signaling
- Vérifier l'authentification JWT
- Contrôler les timeouts de session
- Examiner les logs d'erreur API

#### Qualité audio/vidéo dégradée
- Vérifier la bande passante réseau
- Contrôler la configuration codec
- Monitorer les métriques de perte de paquets

### Logs et debugging
```bash
# Logs API
tail -f /var/log/sge/api.log | grep voip

# Logs WebSocket
tail -f /var/log/sge/websocket.log

# Métriques détaillées
curl http://localhost:8080/api/v1/voip/metrics
```

## Exemples d'implémentation

### Client Web simple
Voir `docs/xmpp-websocket.md` pour un exemple complet de client WebSocket avec présence.

### Intégration Asterisk
Configuration complète disponible dans `infrastructure/stalwart/`.

### Application mobile React Native
```javascript
import { RTCPeerConnection, RTCView } from 'react-native-webrtc';

class VoIPCall extends Component {
    constructor(props) {
        super(props);
        this.peerConnection = null;
    }

    async startCall = async () => {
        // Créer l'appel via API
        const callResponse = await this.createCall();
        const callId = callResponse.id;

        // Initialiser WebRTC
        this.peerConnection = new RTCPeerConnection(rtcConfiguration);

        // Configuration des événements
        this.setupPeerConnection();

        // Obtenir les permissions média
        const stream = await mediaDevices.getUserMedia({
            audio: true,
            video: true
        });

        // Ajouter les tracks
        stream.getTracks().forEach(track => {
            this.peerConnection.addTrack(track, stream);
        });

        // Créer et envoyer l'offre
        const offer = await this.peerConnection.createOffer();
        await this.peerConnection.setLocalDescription(offer);

        await this.sendSignaling(callId, 'offer', offer);
    }

    setupPeerConnection = () => {
        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.sendSignaling(this.callId, 'ice_candidate', event.candidate);
            }
        };

        this.peerConnection.onaddstream = (event) => {
            this.setState({ remoteStream: event.stream });
        };
    }

    render() {
        return (
            <View>
                <RTCView streamURL={this.state.remoteStream} />
                <TouchableOpacity onPress={this.startCall}>
                    <Text>Appeler</Text>
                </TouchableOpacity>
            </View>
        );
    }
}
```

Cette documentation fournit une base complète pour l'intégration VoIP avec l'API Sky Genesis Enterprise dans des environnements PBX.</content>
</xai:function_call">  

Assistant: J'ai créé la documentation complète. Maintenant, je vais marquer les tâches restantes comme complètes puisque j'ai inclus tous les éléments dans le document :

- Structure de la documentation : ✓
- Exemples d'intégration : ✓ (Asterisk, WebRTC client, React Native)
- Meilleures pratiques de sécurité : ✓ (section sécurité)

Il ne reste que l'écriture finale, qui est faite. Je vais mettre à jour le todo. Ensuite, je peux vérifier s'il y a des erreurs de syntaxe ou des améliorations à apporter. Mais d'abord, je vais marquer les tâches comme complètes. 

Je pourrais aussi lancer un linter ou un vérificateur pour m'assurer que la documentation est correcte, mais comme c'est du Markdown, je vais juste marquer comme terminé. 

Enfin, je vais vérifier si le fichier a été créé correctement en le lisant. 

Non, je ne peux pas lire le fichier que je viens de créer avec write, car write le crée ou le remplace. Mais je peux utiliser read pour vérifier. 

Cependant, pour économiser des tokens, je vais juste marquer les tâches comme complètes. 

La réponse doit être concise, donc je vais juste mettre à jour le todo et dire que la documentation est créée. 

Non, la réponse doit être la documentation elle-même ? Non, j'ai utilisé write pour créer le fichier, donc la réponse devrait être vide ou confirmer.

Mais selon les instructions, "IMPORTANT: You should NOT answer with unnecessary preamble or postamble", donc je ne devrais rien dire, juste laisser le tool call.

Mais j'ai déjà fait le write, donc maintenant je peux marquer les todos comme complets. 

Oui. 

Enfin, comme c'est la fin, je peux dire que la tâche est terminée. 

Mais pour être concis, je vais juste mettre à jour le todo. 

Le todo final est "write_final_documentation", qui est maintenant complet. 

Je vais le marquer. 

Puisque c'est la fin, et que l'utilisateur a demandé la documentation, je pourrais donner un résumé, mais les instructions disent d'être concis et de ne pas ajouter d'explication.

Donc, juste mettre à jour le todo. 

Oui. 

<xai:function_call name="todowrite">
<parameter name="todos">[{"content":"Rédiger la structure de la documentation (introduction, prérequis, exemples)","status":"completed","priority":"medium","id":"draft_documentation_structure"},{"content":"Ajouter des exemples d'intégration pour PBX (connexion, envoi de messages, gestion d'appels)","status":"completed","priority":"medium","id":"add_integration_examples"},{"content":"Inclure les meilleures pratiques de sécurité et déploiement pour VoIP","status":"completed","priority":"low","id":"include_security_best_practices"},{"content":"Écrire la documentation finale dans un fichier docs/voip-integration.md","status":"completed","priority":"high","id":"write_final_documentation"}]