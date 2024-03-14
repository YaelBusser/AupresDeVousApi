// Importation du module Express
import express from "express";
import mysql from "mysql";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

// Création d'une instance d'Express
const app = express();
const PORT = process.env.PORT || 3000; // Utilisation du port 3000 par défaut


// Configuration de la connexion à la base de données
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    mdp: '',
    database: 'aupresdevous'
});

// Établissement de la connexion à la base de données
connection.connect(err => {
    if (err) {
        console.error('Erreur de connexion à la base de données :', err);
        return;
    }
    console.log('Connexion à la base de données réussie');
});
// Route d'accueil
app.get('/', (req, res) => {
    res.send('Bienvenue sur votre API !');
});

app.get('/users', (req, res) => {
    connection.query('SELECT * FROM users', (err, results) => {
        if (err) {
            console.error('Erreur lors de la récupération des utilisateurs :', err);
            res.status(500).send('Erreur lors de la récupération des utilisateurs');
            return;
        }
        res.json(results);
    });
});

// Route pour s'enregistrer
app.post('/register', async (req, res) => {
    const { nom, prenom, mail, mdp } = req.body;
    try {
        // Vérifier si l'utilisateur existe déjà dans la base de données
        const existingUser = await new Promise((resolve, reject) => {
            connection.query('SELECT * FROM users WHERE mail = ?', [mail], (err, results) => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve(results[0]);
            });
        });

        if (existingUser) {
            res.status(409).send('Adresse e-mail déjà utilisée');
            return;
        }

        // Hacher le mot de passe avec bcrypt
        const hashedPassword = await bcrypt.hash(mdp, 10);

        // Insérer le nouvel utilisateur dans la base de données avec le mot de passe haché
        await new Promise((resolve, reject) => {
            connection.query('INSERT INTO users (nom, prenom, mail, mdp) VALUES (?, ?, ?, ?)', [nom, prenom, mail, hashedPassword], (err, results) => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve();
            });
        });

        res.status(201).send('Utilisateur enregistré avec succès');
    } catch (error) {
        console.error('Erreur lors de l\'enregistrement de l\'utilisateur :', error);
        res.status(500).send('Erreur lors de l\'enregistrement');
    }
});

// Route pour se connecter
app.post('/login', async (req, res) => {
    const { mail, mdp } = req.body;
    // Récupérer le mot de passe haché de l'utilisateur à partir de la base de données
    connection.query('SELECT * FROM users WHERE mail = ?', [mail], async (err, results) => {
        if (err) {
            console.error('Erreur lors de la récupération des informations de connexion :', err);
            res.status(500).send('Erreur lors de la connexion');
            return;
        }
        if (results.length === 0) {
            res.status(401).send('Nom d\'utilisateur ou mot de passe incorrect');
            return;
        }
        const user = results[0];
        // Comparer le mot de passe fourni avec le mot de passe haché stocké dans la base de données
        const mdpMatch = await bcrypt.compare(mdp, user.mdp);
        if (mdpMatch) {
            // Générer un token JWT
            const token = jwt.sign({ userId: user.id }, 'votre_secret_key', {expiresIn: "7d"});
            // Stocker le token dans la base de données
            connection.query('INSERT INTO authUsers (userId, token) VALUES (?, ?)', [user.id, token], (err, results) => {
                if (err) {
                    console.error('Erreur lors de la génération du token :', err);
                    res.status(500).send('Erreur lors de la connexion');
                    return;
                }
                // Renvoyer le token dans la réponse
                res.status(200).json({ message: 'Connexion réussie', token });
            });
        } else {
            res.status(401).send('Nom d\'utilisateur ou mot de passe incorrect');
        }
    });
});

// Route pour rafraîchir le token
app.post('/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;

    // Vérifier si le token de rafraîchissement est valide
    jwt.verify(refreshToken, 'votre_secret_key', (err, decoded) => {
        if (err) {
            console.error('Erreur de vérification du token de rafraîchissement :', err);
            res.status(401).send('Token de rafraîchissement invalide');
            return;
        }

        // Générer un nouveau token d'authentification avec une durée de validité plus longue
        const newToken = jwt.sign({ userId: decoded.userId }, 'votre_secret_key', { expiresIn: '7d' });

        // Renvoyer le nouveau token d'authentification au client
        res.status(200).json({ message: 'Nouveau token généré avec succès', token: newToken });
    });
});

// Démarrage du serveur
app.listen(PORT, () => {
    console.log(`Le serveur est en écoute sur le port http://localhost:${PORT}`);
});
