using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SkyServer
{
    internal sealed class SkyDatabase
    {
        private const int PasswordIterations = 100000;
        private const int PasswordHashBytes = 32;
        private readonly string dbPath;
        private readonly string sqlitePath;
        private readonly object syncRoot = new object();

        public SkyDatabase(string dbPath, string sqlitePath)
        {
            this.dbPath = Path.GetFullPath(dbPath);
            this.sqlitePath = sqlitePath;
            string directory = Path.GetDirectoryName(this.dbPath);
            if (!String.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }

        public void EnsureSchema()
        {
            Execute(@"
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_utc TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS contacts (
    owner_login TEXT NOT NULL,
    contact_login TEXT NOT NULL,
    created_utc TEXT NOT NULL,
    PRIMARY KEY(owner_login, contact_login),
    FOREIGN KEY(owner_login) REFERENCES accounts(login) ON DELETE CASCADE,
    FOREIGN KEY(contact_login) REFERENCES accounts(login) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS native_password_verifiers (
    login TEXT PRIMARY KEY,
    salt TEXT NOT NULL,
    verifier TEXT NOT NULL,
    FOREIGN KEY(login) REFERENCES accounts(login) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS account_profiles (
    login TEXT PRIMARY KEY,
    email TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(login) REFERENCES accounts(login) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    login TEXT NOT NULL,
    created_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL,
    FOREIGN KEY(login) REFERENCES accounts(login) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_login TEXT NOT NULL,
    recipient_login TEXT NOT NULL,
    body TEXT NOT NULL,
    created_utc TEXT NOT NULL,
    delivered_utc TEXT,
    FOREIGN KEY(sender_login) REFERENCES accounts(login) ON DELETE CASCADE,
    FOREIGN KEY(recipient_login) REFERENCES accounts(login) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_login);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_login, recipient_login, id);
");
        }

        public void AddAccount(string login, string displayName, string password)
        {
            if (String.IsNullOrWhiteSpace(login))
            {
                throw new ArgumentException("login is required");
            }

            byte[] salt = new byte[16];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            string saltText = Convert.ToBase64String(salt);
            string hashText = Convert.ToBase64String(HashPassword(password, salt));
            string now = Now();

            int exists = ToInt(QuerySingle("SELECT COUNT(*) FROM accounts WHERE login = " + Sql(login) + ";"), 0);
            string accountSql;
            if (exists > 0)
            {
                accountSql = "UPDATE accounts SET display_name = " + Sql(displayName) +
                    ", password_salt = " + Sql(saltText) +
                    ", password_hash = " + Sql(hashText) +
                    ", is_active = 1 WHERE login = " + Sql(login) + ";";
            }
            else
            {
                accountSql = "INSERT INTO accounts(login, display_name, password_salt, password_hash, created_utc, is_active) VALUES (" +
                    Sql(login) + ", " + Sql(displayName) + ", " + Sql(saltText) + ", " + Sql(hashText) + ", " + Sql(now) + ", 1);";
            }
            string nativeSalt, nativeVerifier;
            MakeNativeVerifier(login, password, out nativeSalt, out nativeVerifier);
            Execute("BEGIN IMMEDIATE;" + accountSql +
                "INSERT OR REPLACE INTO native_password_verifiers(login,salt,verifier) VALUES (" +
                Sql(login) + "," + Sql(nativeSalt) + "," + Sql(nativeVerifier) + "); COMMIT;");
        }

        public void RemoveAccount(string login)
        {
            Execute("DELETE FROM accounts WHERE login = " + Sql(login) + ";");
        }

        public void AddContact(string ownerLogin, string contactLogin)
        {
            if (GetAccount(ownerLogin) == null)
            {
                throw new InvalidOperationException("owner account does not exist: " + ownerLogin);
            }

            if (GetAccount(contactLogin) == null)
            {
                throw new InvalidOperationException("contact account does not exist: " + contactLogin);
            }

            Execute("INSERT OR IGNORE INTO contacts(owner_login, contact_login, created_utc) VALUES (" +
                Sql(ownerLogin) + ", " + Sql(contactLogin) + ", " + Sql(Now()) + ");");
        }

        public bool ValidatePassword(string login, string password)
        {
            Account ignored;
            return ValidatePassword(login, password, out ignored);
        }

        public bool ValidatePassword(string login, string password, out Account account)
        {
            account = null;
            string line = QuerySingle("SELECT login, display_name, password_salt, password_hash FROM accounts WHERE login = " +
                Sql(login) + " AND is_active = 1;");
            if (String.IsNullOrEmpty(line))
            {
                return false;
            }

            string[] parts = SplitRow(line);
            if (parts.Length < 4)
            {
                return false;
            }

            byte[] salt = Convert.FromBase64String(parts[2]);
            byte[] expected = Convert.FromBase64String(parts[3]);
            byte[] actual = HashPassword(password, salt);
            if (!ConstantTimeEquals(expected, actual))
            {
                return false;
            }

            account = new Account { Login = parts[0], DisplayName = parts[1] };
            // Existing PBKDF2 hashes cannot be converted without a verified password.
            if (ToInt(QuerySingle("SELECT COUNT(*) FROM native_password_verifiers WHERE login=" + Sql(login) + ";"), 0) == 0)
            {
                string nativeSalt, nativeVerifier;
                MakeNativeVerifier(login, password, out nativeSalt, out nativeVerifier);
                Execute("INSERT OR IGNORE INTO native_password_verifiers(login,salt,verifier) SELECT login," +
                    Sql(nativeSalt) + "," + Sql(nativeVerifier) + " FROM accounts WHERE login=" + Sql(login) +
                    " AND password_salt=" + Sql(parts[2]) + " AND password_hash=" + Sql(parts[3]) + " AND is_active=1;");
            }
            return true;
        }

        public bool ValidateNativePasswordHash(string login, byte[] digest)
        {
            if (digest == null || digest.Length != 16) return false;
            string row = QuerySingle("SELECT v.salt,v.verifier FROM native_password_verifiers v JOIN accounts a ON a.login=v.login WHERE a.is_active=1 AND v.login=" + Sql(login) + ";");
            if (String.IsNullOrEmpty(row)) return false;
            string[] parts = SplitRow(row);
            if (parts.Length != 2) return false;
            using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(digest, Convert.FromBase64String(parts[0]), PasswordIterations))
                return ConstantTimeEquals(Convert.FromBase64String(parts[1]), kdf.GetBytes(PasswordHashBytes));
        }

        internal static byte[] NativePasswordDigest(string login, string password)
        {
            byte[] input = Encoding.UTF8.GetBytes(login + "\nskyper\n" + password);
            try { using (MD5 md5 = MD5.Create()) return md5.ComputeHash(input); }
            finally { Array.Clear(input, 0, input.Length); }
        }

        private static void MakeNativeVerifier(string login, string password, out string saltText, out string verifier)
        {
            byte[] salt = new byte[16];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(salt);
            byte[] digest = NativePasswordDigest(login, password);
            try
            {
                using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(digest, salt, PasswordIterations))
                    verifier = Convert.ToBase64String(kdf.GetBytes(PasswordHashBytes));
                saltText = Convert.ToBase64String(salt);
            }
            finally { Array.Clear(digest, 0, digest.Length); }
        }

        public void RequirePassword(string login, string password)
        {
            if (!ValidatePassword(login, password))
            {
                throw new InvalidOperationException("invalid credentials");
            }
        }

        public string GetAccountEmail(string login)
        {
            if (GetAccount(login) == null) throw new InvalidOperationException("Account does not exist");
            return QuerySingle("SELECT email FROM account_profiles WHERE login=" + Sql(login) + ";") ?? "";
        }

        public void SetAccountEmail(string login, string email)
        {
            if (email == null || email.Length > 254 || email.IndexOfAny(new[] { '\0', '\r', '\n', '\t', ' ' }) >= 0)
                throw new ArgumentException("Invalid account email");
            if (email.Length > 0)
            {
                System.Net.Mail.MailAddress parsed = new System.Net.Mail.MailAddress(email);
                if (parsed.Address != email) throw new ArgumentException("Expected an email address without a display name");
            }
            if (GetAccount(login) == null) throw new InvalidOperationException("Account does not exist");
            Execute("INSERT OR REPLACE INTO account_profiles(login,email) VALUES (" + Sql(login) + "," + Sql(email) + ");");
        }

        public Account GetAccount(string login)
        {
            string line = QuerySingle("SELECT login, display_name FROM accounts WHERE login = " + Sql(login) + " AND is_active = 1;");
            if (String.IsNullOrEmpty(line))
            {
                return null;
            }

            string[] parts = SplitRow(line);
            return new Account { Login = parts[0], DisplayName = parts.Length > 1 ? parts[1] : parts[0] };
        }

        public List<Account> GetContacts(string ownerLogin)
        {
            List<Account> contacts = new List<Account>();
            string output = Query("SELECT a.login, a.display_name FROM contacts c JOIN accounts a ON a.login = c.contact_login " +
                "WHERE c.owner_login = " + Sql(ownerLogin) + " AND a.is_active = 1 ORDER BY a.display_name COLLATE NOCASE;");
            foreach (string line in SplitLines(output))
            {
                string[] parts = SplitRow(line);
                if (parts.Length >= 2)
                {
                    contacts.Add(new Account { Login = parts[0], DisplayName = parts[1] });
                }
            }

            return contacts;
        }

        public string CreateSession(string login)
        {
            string token = NewToken();
            string now = Now();
            Execute("INSERT INTO sessions(token, login, created_utc, last_seen_utc) VALUES (" +
                Sql(token) + ", " + Sql(login) + ", " + Sql(now) + ", " + Sql(now) + ");");
            return token;
        }

        public long SendMessage(string senderLogin, string recipientLogin, string body)
        {
            if (GetAccount(recipientLogin) == null)
            {
                throw new InvalidOperationException("recipient does not exist");
            }

            int isContact = ToInt(QuerySingle("SELECT COUNT(*) FROM contacts WHERE owner_login = " + Sql(senderLogin) +
                " AND contact_login = " + Sql(recipientLogin) + ";"), 0);
            if (isContact == 0)
            {
                throw new InvalidOperationException("recipient is not in contact list");
            }

            Execute("INSERT INTO messages(sender_login, recipient_login, body, created_utc) VALUES (" +
                Sql(senderLogin) + ", " + Sql(recipientLogin) + ", " + Sql(body) + ", " + Sql(Now()) + ");");
            return ToLong(QuerySingle("SELECT MAX(id) FROM messages WHERE sender_login = " + Sql(senderLogin) +
                " AND recipient_login = " + Sql(recipientLogin) + ";"), 0);
        }

        public List<MessageRecord> ReceiveMessages(string recipientLogin, string peerLogin)
        {
            List<MessageRecord> messages = SelectMessages("SELECT id, sender_login, recipient_login, hex(CAST(body AS BLOB)), created_utc, COALESCE(delivered_utc, '') " +
                "FROM messages WHERE sender_login = " + Sql(peerLogin) + " AND recipient_login = " + Sql(recipientLogin) +
                " AND delivered_utc IS NULL ORDER BY id;");
            if (messages.Count > 0)
            {
                StringBuilder ids = new StringBuilder();
                for (int i = 0; i < messages.Count; i++)
                {
                    if (i > 0)
                    {
                        ids.Append(',');
                    }

                    ids.Append(messages[i].Id.ToString(CultureInfo.InvariantCulture));
                }

                Execute("UPDATE messages SET delivered_utc = " + Sql(Now()) + " WHERE id IN (" + ids + ");");
            }

            return messages;
        }

        public List<MessageRecord> GetHistory(string login, string peerLogin)
        {
            return SelectMessages("SELECT id, sender_login, recipient_login, hex(CAST(body AS BLOB)), created_utc, COALESCE(delivered_utc, '') " +
                "FROM messages WHERE (sender_login = " + Sql(login) + " AND recipient_login = " + Sql(peerLogin) + ") OR " +
                "(sender_login = " + Sql(peerLogin) + " AND recipient_login = " + Sql(login) + ") ORDER BY id;");
        }

        public string BuildVcard(string login)
        {
            byte[] hash;
            using (SHA1 sha1 = SHA1.Create())
            {
                hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(login));
            }

            StringBuilder id = new StringBuilder("0x");
            for (int i = 0; i < 8; i++)
            {
                id.Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
            }

            return id + "-s127.0.0.1:33034-r127.0.0.1:33034-l127.0.0.1:33034";
        }

        private List<MessageRecord> SelectMessages(string sql)
        {
            List<MessageRecord> messages = new List<MessageRecord>();
            string output = Query(sql);
            foreach (string line in SplitLines(output))
            {
                string[] parts = SplitRow(line);
                if (parts.Length >= 6)
                {
                    messages.Add(new MessageRecord
                    {
                        Id = ToLong(parts[0], 0),
                        SenderLogin = parts[1],
                        RecipientLogin = parts[2],
                        Body = DecodeHexUtf8(parts[3]),
                        CreatedUtc = parts[4],
                        DeliveredUtc = parts[5]
                    });
                }
            }

            return messages;
        }

        private string QuerySingle(string sql)
        {
            foreach (string line in SplitLines(Query(sql)))
            {
                return line;
            }

            return "";
        }

        private string Query(string sql)
        {
            return Execute(sql);
        }

        private string Execute(string sql)
        {
            lock (syncRoot)
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = sqlitePath;
                psi.Arguments = QuoteArg(dbPath) + " -batch -noheader -tabs";
                psi.UseShellExecute = false;
                psi.RedirectStandardInput = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;

                using (Process process = Process.Start(psi))
                {
                    process.StandardInput.WriteLine("PRAGMA foreign_keys=ON;");
                    process.StandardInput.WriteLine(sql);
                    process.StandardInput.Close();

                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                    if (process.ExitCode != 0)
                    {
                        throw new InvalidOperationException("sqlite failed: " + error);
                    }

                    return output;
                }
            }
        }

        private static string Sql(string value)
        {
            return "'" + (value ?? "").Replace("'", "''") + "'";
        }

        private static string QuoteArg(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static byte[] HashPassword(string password, byte[] salt)
        {
            using (Rfc2898DeriveBytes pbkdf = new Rfc2898DeriveBytes(password ?? "", salt, PasswordIterations))
            {
                return pbkdf.GetBytes(PasswordHashBytes);
            }
        }

        private static bool ConstantTimeEquals(byte[] expected, byte[] actual)
        {
            if (expected == null || actual == null || expected.Length != actual.Length)
            {
                return false;
            }

            int diff = 0;
            for (int i = 0; i < expected.Length; i++)
            {
                diff |= expected[i] ^ actual[i];
            }

            return diff == 0;
        }

        private static string NewToken()
        {
            byte[] data = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(data);
            }

            return Convert.ToBase64String(data);
        }

        private static string Now()
        {
            return DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        }

        private static int ToInt(string value, int fallback)
        {
            int parsed;
            return Int32.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed) ? parsed : fallback;
        }

        private static long ToLong(string value, long fallback)
        {
            long parsed;
            return Int64.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed) ? parsed : fallback;
        }

        private static string[] SplitLines(string text)
        {
            return (text ?? "").Replace("\r", "").Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        }

        private static string[] SplitRow(string row)
        {
            return (row ?? "").Split('\t');
        }

        private static string DecodeHexUtf8(string hex)
        {
            if (String.IsNullOrEmpty(hex))
            {
                return "";
            }

            byte[] data = new byte[hex.Length / 2];
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return Encoding.UTF8.GetString(data);
        }
    }

    internal sealed class Account
    {
        public string Login;
        public string DisplayName;
    }

    internal sealed class MessageRecord
    {
        public long Id;
        public string SenderLogin;
        public string RecipientLogin;
        public string Body;
        public string CreatedUtc;
        public string DeliveredUtc;
    }
}
