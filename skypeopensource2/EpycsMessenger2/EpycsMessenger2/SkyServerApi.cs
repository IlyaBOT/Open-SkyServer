using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Net;
using System.Text;

namespace EpycsMessenger2
{
    internal static class SkyServerApi
    {
        public static string BaseUrl
        {
            get
            {
                string host = Environment.GetEnvironmentVariable("SKYSERVER_HOST");
                if (String.IsNullOrEmpty(host))
                {
                    host = Environment.GetEnvironmentVariable("SKYAUTH_HOST");
                }

                if (String.IsNullOrEmpty(host))
                {
                    host = "127.0.0.1";
                }

                string port = Environment.GetEnvironmentVariable("SKYSERVER_API_PORT");
                if (String.IsNullOrEmpty(port))
                {
                    port = "33034";
                }

                return "http://" + host + ":" + port;
            }
        }

        public static List<SkyContact> GetContacts(string user, string password)
        {
            ApiResponse response = Post("/api/contacts", AuthFields(user, password));
            List<SkyContact> contacts = new List<SkyContact>();
            for (int i = 1; i < response.Lines.Length; i++)
            {
                if (String.IsNullOrWhiteSpace(response.Lines[i]))
                {
                    continue;
                }

                string[] parts = response.Lines[i].Split('\t');
                if (parts.Length >= 3)
                {
                    contacts.Add(new SkyContact
                    {
                        Login = Decode(parts[0]),
                        DisplayName = Decode(parts[1]),
                        Vcard = Decode(parts[2])
                    });
                }
            }

            return contacts;
        }

        public static SkyContact GetProfile(string user, string password, string target)
        {
            NameValueCollection fields = AuthFields(user, password);
            fields["target"] = target;
            ApiResponse response = Post("/api/profile", fields);
            if (response.Lines.Length < 2)
            {
                throw new InvalidOperationException("Empty profile response.");
            }

            string[] parts = response.Lines[1].Split('\t');
            if (parts.Length < 3)
            {
                throw new InvalidOperationException("Bad profile response.");
            }

            return new SkyContact
            {
                Login = Decode(parts[0]),
                DisplayName = Decode(parts[1]),
                Vcard = Decode(parts[2])
            };
        }

        public static string GetMyAddress(string user, string password)
        {
            ApiResponse response = Post("/api/myaddr", AuthFields(user, password));
            return response.Lines.Length > 1 ? response.Lines[1].Trim() : "127.0.0.1";
        }

        public static long SendMessage(string user, string password, string recipient, string body)
        {
            NameValueCollection fields = AuthFields(user, password);
            fields["recipient"] = recipient;
            fields["body"] = body;
            ApiResponse response = Post("/api/message/send", fields);
            if (response.Lines.Length < 2)
            {
                return 0;
            }

            long id;
            return Int64.TryParse(response.Lines[1].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out id) ? id : 0;
        }

        public static List<SkyMessage> ReceiveMessages(string user, string password, string peer)
        {
            NameValueCollection fields = AuthFields(user, password);
            fields["peer"] = peer;
            return ParseMessages(Post("/api/message/recv", fields));
        }

        public static List<SkyMessage> LoadHistory(string user, string password, string peer)
        {
            NameValueCollection fields = AuthFields(user, password);
            fields["peer"] = peer;
            return ParseMessages(Post("/api/history", fields));
        }

        public static string FormatHistory(string localUser, List<SkyMessage> messages)
        {
            StringBuilder result = new StringBuilder();
            foreach (SkyMessage message in messages)
            {
                DateTime created;
                string stamp = message.CreatedUtc;
                if (DateTime.TryParse(message.CreatedUtc, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out created))
                {
                    stamp = created.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
                }

                string sender = message.SenderLogin == localUser ? "me" : message.SenderLogin;
                result.Append("[");
                result.Append(stamp);
                result.Append("] ");
                result.Append(sender);
                result.Append(": ");
                result.Append(message.Body);
                result.Append("\n");
            }

            return result.ToString();
        }

        private static List<SkyMessage> ParseMessages(ApiResponse response)
        {
            List<SkyMessage> messages = new List<SkyMessage>();
            for (int i = 1; i < response.Lines.Length; i++)
            {
                if (String.IsNullOrWhiteSpace(response.Lines[i]))
                {
                    continue;
                }

                string[] parts = response.Lines[i].Split('\t');
                if (parts.Length >= 5)
                {
                    long id;
                    Int64.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out id);
                    messages.Add(new SkyMessage
                    {
                        Id = id,
                        SenderLogin = Decode(parts[1]),
                        RecipientLogin = Decode(parts[2]),
                        Body = Decode(parts[3]),
                        CreatedUtc = Decode(parts[4])
                    });
                }
            }

            return messages;
        }

        private static NameValueCollection AuthFields(string user, string password)
        {
            NameValueCollection fields = new NameValueCollection();
            fields["user"] = user;
            fields["password"] = password;
            return fields;
        }

        private static ApiResponse Post(string path, NameValueCollection fields)
        {
            using (WebClient client = new WebClient())
            {
                client.Encoding = Encoding.UTF8;
                byte[] bytes = client.UploadValues(BaseUrl + path, "POST", fields);
                string text = Encoding.UTF8.GetString(bytes);
                string[] lines = text.Replace("\r", "").Split('\n');
                if (lines.Length == 0 || lines[0] != "OK")
                {
                    string error = lines.Length > 0 ? Decode(lines[0]) : "empty response";
                    if (lines.Length > 1)
                    {
                        error = Decode(lines[1]);
                    }

                    throw new InvalidOperationException(error);
                }

                return new ApiResponse { Lines = lines };
            }
        }

        private static string Decode(string value)
        {
            return Uri.UnescapeDataString((value ?? "").Replace("+", " "));
        }

        private sealed class ApiResponse
        {
            public string[] Lines;
        }
    }

    internal sealed class SkyContact
    {
        public string Login;
        public string DisplayName;
        public string Vcard;
    }

    internal sealed class SkyMessage
    {
        public long Id;
        public string SenderLogin;
        public string RecipientLogin;
        public string Body;
        public string CreatedUtc;
    }
}
