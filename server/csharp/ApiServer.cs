using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SkyServer
{
    internal sealed class ApiServer
    {
        private readonly SkyDatabase database;
        private readonly IPAddress bindAddress;
        private readonly int port;
        private TcpListener listener;
        private volatile bool stopped;

        private readonly NetworkAccessPolicy access;
        private readonly Semaphore connectionSlots = new Semaphore(32, 32);
        public ApiServer(SkyDatabase database, IPAddress bindAddress, int port, NetworkAccessPolicy access = null)
        {
            this.access = access ?? NetworkAccessPolicy.Open;
            this.database = database;
            this.bindAddress = bindAddress;
            this.port = port;
        }

        public void Run()
        {
            listener = new TcpListener(bindAddress, port);
            listener.Start();
            Console.WriteLine("api listening on {0}:{1}", bindAddress, port);

            while (!stopped)
            {
                try
                {
                    TcpClient client = listener.AcceptTcpClient();
                    if (!access.Accept(client)) continue;
                    if (!connectionSlots.WaitOne(0)) { client.Close(); continue; }
                    ThreadPool.QueueUserWorkItem(delegate(object item) {
                        try { HandleClient(item); }
                        finally { connectionSlots.Release(); }
                    }, client);
                }
                catch (SocketException)
                {
                    if (!stopped)
                    {
                        throw;
                    }
                }
                catch (ObjectDisposedException)
                {
                    if (!stopped)
                    {
                        throw;
                    }
                }
            }
        }

        public void Stop()
        {
            stopped = true;
            if (listener != null)
            {
                listener.Stop();
            }
        }

        private void HandleClient(object state)
        {
            using (TcpClient client = (TcpClient)state)
            {
                try
                {
                    client.ReceiveTimeout = 10000;
                    client.SendTimeout = 10000;
                    string response = HandleRequest(client.GetStream());
                    WriteResponse(client.GetStream(), 200, response);
                }
                catch (Exception ex)
                {
                    try
                    {
                        WriteResponse(client.GetStream(), 500, "ERR\t" + Encode(ex.Message) + "\n");
                    }
                    catch
                    {
                    }
                }
            }
        }

        private string HandleRequest(NetworkStream stream)
        {
            HttpRequest request = ReadRequest(stream);
            if (request.Method != "POST")
            {
                return "ERR\tmethod_not_allowed\n";
            }

            Dictionary<string, string> form = ParseForm(request.Body);
            if (request.Path == "/api/login")
            {
                string user = Get(form, "user");
                string password = Get(form, "password");
                Account account;
                if (!database.ValidatePassword(user, password, out account))
                {
                    return "ERR\tinvalid_credentials\n";
                }

                string token = database.CreateSession(user);
                return "OK\n" + Encode(token) + "\t" + Encode(account.DisplayName) + "\n";
            }

            if (request.Path == "/api/contacts")
            {
                string user = Get(form, "user");
                string password = Get(form, "password");
                database.RequirePassword(user, password);
                List<Account> contacts = database.GetContacts(user);
                StringBuilder result = new StringBuilder();
                result.Append("OK\n");
                foreach (Account contact in contacts)
                {
                    result.Append(Encode(contact.Login));
                    result.Append('\t');
                    result.Append(Encode(contact.DisplayName));
                    result.Append('\t');
                    result.Append(Encode(database.BuildVcard(contact.Login)));
                    result.Append('\n');
                }

                return result.ToString();
            }

            if (request.Path == "/api/profile")
            {
                string user = Get(form, "user");
                string password = Get(form, "password");
                string target = Get(form, "target");
                database.RequirePassword(user, password);
                Account account = database.GetAccount(target);
                if (account == null)
                {
                    return "ERR\tunknown_account\n";
                }

                return "OK\n" + Encode(account.Login) + "\t" + Encode(account.DisplayName) + "\t" + Encode(database.BuildVcard(account.Login)) + "\n";
            }

            if (request.Path == "/api/myaddr")
            {
                string user = Get(form, "user");
                string password = Get(form, "password");
                database.RequirePassword(user, password);
                return "OK\n127.0.0.1\n";
            }

            if (request.Path == "/api/message/send")
            {
                string user = Get(form, "user");
                string password = Get(form, "password");
                string recipient = Get(form, "recipient");
                string body = Get(form, "body");
                database.RequirePassword(user, password);
                long id = database.SendMessage(user, recipient, body);
                return "OK\n" + id.ToString() + "\n";
            }

            if (request.Path == "/api/message/recv")
            {
                string user = Get(form, "user");
                string password = Get(form, "password");
                string peer = Get(form, "peer");
                database.RequirePassword(user, password);
                List<MessageRecord> messages = database.ReceiveMessages(user, peer);
                return FormatMessages(messages);
            }

            if (request.Path == "/api/history")
            {
                string user = Get(form, "user");
                string password = Get(form, "password");
                string peer = Get(form, "peer");
                database.RequirePassword(user, password);
                List<MessageRecord> messages = database.GetHistory(user, peer);
                return FormatMessages(messages);
            }

            return "ERR\tunknown_endpoint\n";
        }

        private static string FormatMessages(List<MessageRecord> messages)
        {
            StringBuilder result = new StringBuilder();
            result.Append("OK\n");
            foreach (MessageRecord message in messages)
            {
                result.Append(message.Id);
                result.Append('\t');
                result.Append(Encode(message.SenderLogin));
                result.Append('\t');
                result.Append(Encode(message.RecipientLogin));
                result.Append('\t');
                result.Append(Encode(message.Body));
                result.Append('\t');
                result.Append(Encode(message.CreatedUtc));
                result.Append('\n');
            }

            return result.ToString();
        }

        private static HttpRequest ReadRequest(NetworkStream stream)
        {
            List<byte> headerBytes = new List<byte>();
            int matched = 0;
            byte[] end = { 13, 10, 13, 10 };
            while (true)
            {
                int value = stream.ReadByte();
                if (value < 0)
                {
                    throw new EndOfStreamException("socket closed while reading HTTP headers");
                }

                headerBytes.Add((byte)value);
                matched = value == end[matched] ? matched + 1 : (value == end[0] ? 1 : 0);
                if (matched == end.Length)
                {
                    break;
                }

                if (headerBytes.Count > 32768)
                {
                    throw new InvalidDataException("HTTP headers too large");
                }
            }

            string headers = Encoding.ASCII.GetString(headerBytes.ToArray());
            string[] lines = headers.Replace("\r", "").Split('\n');
            string[] first = lines[0].Split(' ');
            if (first.Length < 2)
            {
                throw new InvalidDataException("bad HTTP request line");
            }

            int contentLength = 0;
            for (int i = 1; i < lines.Length; i++)
            {
                int p = lines[i].IndexOf(':');
                if (p > 0 && lines[i].Substring(0, p).Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    contentLength = Int32.Parse(lines[i].Substring(p + 1).Trim());
                }
            }

            byte[] body = new byte[contentLength];
            int offset = 0;
            while (offset < contentLength)
            {
                int read = stream.Read(body, offset, contentLength - offset);
                if (read <= 0)
                {
                    throw new EndOfStreamException("socket closed while reading HTTP body");
                }

                offset += read;
            }

            return new HttpRequest
            {
                Method = first[0],
                Path = first[1],
                Body = Encoding.UTF8.GetString(body)
            };
        }

        private static void WriteResponse(NetworkStream stream, int status, string body)
        {
            byte[] payload = Encoding.UTF8.GetBytes(body);
            string header = "HTTP/1.1 " + status + " " + (status == 200 ? "OK" : "Error") + "\r\n" +
                "Content-Type: text/plain; charset=utf-8\r\n" +
                "Content-Length: " + payload.Length + "\r\n" +
                "Connection: close\r\n\r\n";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(payload, 0, payload.Length);
        }

        private static Dictionary<string, string> ParseForm(string body)
        {
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (String.IsNullOrEmpty(body))
            {
                return result;
            }

            string[] pairs = body.Split('&');
            foreach (string pair in pairs)
            {
                int p = pair.IndexOf('=');
                if (p >= 0)
                {
                    result[Decode(pair.Substring(0, p))] = Decode(pair.Substring(p + 1));
                }
            }

            return result;
        }

        private static string Get(Dictionary<string, string> form, string name)
        {
            string value;
            return form.TryGetValue(name, out value) ? value : "";
        }

        internal static string Encode(string value)
        {
            return Uri.EscapeDataString(value ?? "");
        }

        internal static string Decode(string value)
        {
            return Uri.UnescapeDataString((value ?? "").Replace("+", " "));
        }

        private sealed class HttpRequest
        {
            public string Method;
            public string Path;
            public string Body;
        }
    }
}
