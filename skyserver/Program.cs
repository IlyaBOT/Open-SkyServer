using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;

namespace SkyServer
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            ServerOptions options = ServerOptions.Parse(args);
            CommunityKeys keys = null;
            if (!String.IsNullOrEmpty(options.KeysDirectory))
            {
                keys = CommunityKeys.Load(options.KeysDirectory);
                Console.WriteLine("community login RSA-1536/e65537 modulus SHA256: {0}", keys.LoginFingerprint);
                Console.WriteLine("community credentials RSA-2048/e65537 modulus SHA256: {0}", keys.CredentialsFingerprint);
            }
            if (options.Command == ServerCommand.CheckKeys)
            {
                if (keys == null) throw new ArgumentException("--check-keys requires --keys-dir");
                Console.WriteLine("RSA private/public pair tests passed. This is not a native client login test.");
                return 0;
            }
            SkyDatabase database = new SkyDatabase(options.DatabasePath, options.SqlitePath);
            database.EnsureSchema();

            if (options.Command == ServerCommand.InitDb)
            {
                Console.WriteLine("database initialized: {0}", options.DatabasePath);
                return 0;
            }

            if (options.Command == ServerCommand.AddAccount)
            {
                database.AddAccount(options.CommandArgs[0], options.CommandArgs[1], options.CommandArgs[2]);
                Console.WriteLine("account stored: {0}", options.CommandArgs[0]);
                return 0;
            }

            if (options.Command == ServerCommand.RemoveAccount)
            {
                database.RemoveAccount(options.CommandArgs[0]);
                Console.WriteLine("account removed: {0}", options.CommandArgs[0]);
                return 0;
            }

            if (options.Command == ServerCommand.SetEmail)
            {
                database.SetAccountEmail(options.CommandArgs[0], options.CommandArgs[1]);
                Console.WriteLine("account email stored");
                return 0;
            }

            if (options.Command == ServerCommand.AddContact)
            {
                database.AddContact(options.CommandArgs[0], options.CommandArgs[1]);
                Console.WriteLine("contact stored: {0} -> {1}", options.CommandArgs[0], options.CommandArgs[1]);
                return 0;
            }

            ApiServer apiServer = new ApiServer(database, options.ApiHost, options.ApiPort);
            Thread apiThread = new Thread(apiServer.Run);
            apiThread.IsBackground = true;
            apiThread.Start();

            ProbeUdpServer udpProbe = null;
            TcpProbeServer tcpProbe = null;
            AuthProtocolServer authServer = new AuthProtocolServer(database, options.AuthHost, options.AuthPort, options.Once, options.RealSkypeProbe, keys);
            if (options.RealSkypeProbe)
            {
                Console.WriteLine("stock Skype development probe: --keys-dir enables native RSA/AES password verification and a community-signed credential response. Original client acceptance is unverified; registration, profile and contacts are not implemented.");
                Console.WriteLine("hosts redirects DNS names only. Direct-IP Skype bootstrap/login connections bypass hosts.");
                List<IPEndPoint> hostCacheEndpoints = options.IncludeHostCacheProbe
                    ? SkypeHostCache.ReadEndpoints(options.SkypeSharedXmlPath)
                    : new List<IPEndPoint>();
                if (options.IncludeHostCacheProbe)
                {
                    Console.WriteLine(
                        "skype HostCache endpoints loaded from {0}: {1} endpoints, {2} ports",
                        options.SkypeSharedXmlPath,
                        hostCacheEndpoints.Count,
                        CountUniquePorts(hostCacheEndpoints));
                }
                else
                {
                    Console.WriteLine("skype HostCache probe listeners disabled; this does not disable the client's supernode role.");
                }

                udpProbe = new ProbeUdpServer(options.AuthHost, BuildProbePorts(options.AuthPort, hostCacheEndpoints));
                Thread udpThread = new Thread(udpProbe.Run);
                udpThread.IsBackground = true;
                udpThread.Start();

                tcpProbe = new TcpProbeServer(options.AuthHost, BuildTcpProbePorts(options.AuthPort, options.ApiPort, hostCacheEndpoints), authServer, keys);
                Thread tcpThread = new Thread(tcpProbe.Run);
                tcpThread.IsBackground = true;
                tcpThread.Start();
            }

            authServer.Run();

            if (udpProbe != null)
            {
                udpProbe.Stop();
            }

            if (tcpProbe != null)
            {
                tcpProbe.Stop();
            }

            apiServer.Stop();
            return 0;
        }

        private static int[] BuildProbePorts(int authPort, IEnumerable<IPEndPoint> extraEndpoints)
        {
            List<int> ports = new List<int>();
            AddPort(ports, authPort);
            AddPort(ports, 12350);
            AddPort(ports, 12351);
            AddPort(ports, 13392);
            for (int port = 40001; port <= 40036; port++)
            {
                AddPort(ports, port);
            }

            AddEndpointPorts(ports, extraEndpoints);
            return ports.ToArray();
        }

        private static int[] BuildTcpProbePorts(int authPort, int apiPort, IEnumerable<IPEndPoint> extraEndpoints)
        {
            List<int> ports = new List<int>();
            AddPort(ports, 80);
            AddPort(ports, 443);
            AddPort(ports, 12350);
            AddPort(ports, 12351);
            AddPort(ports, 13392);
            for (int port = 40001; port <= 40036; port++)
            {
                AddPort(ports, port);
            }

            AddEndpointPorts(ports, extraEndpoints);
            ports.Remove(authPort);
            ports.Remove(apiPort);
            return ports.ToArray();
        }

        private static void AddEndpointPorts(List<int> ports, IEnumerable<IPEndPoint> endpoints)
        {
            foreach (IPEndPoint endpoint in endpoints)
            {
                AddPort(ports, endpoint.Port);
            }
        }

        private static int CountUniquePorts(IEnumerable<IPEndPoint> endpoints)
        {
            List<int> ports = new List<int>();
            foreach (IPEndPoint endpoint in endpoints)
            {
                AddPort(ports, endpoint.Port);
            }

            return ports.Count;
        }

        private static void AddPort(List<int> ports, int port)
        {
            if (!ports.Contains(port))
            {
                ports.Add(port);
            }
        }
    }

    internal enum ServerCommand
    {
        Serve,
        InitDb,
        AddAccount,
        RemoveAccount,
        AddContact,
        SetEmail,
        CheckKeys
    }

    internal sealed class ServerOptions
    {
        public IPAddress AuthHost = IPAddress.Loopback;
        public int AuthPort = 33033;
        public IPAddress ApiHost = IPAddress.Loopback;
        public int ApiPort = 33034;
        public bool Once;
        public bool RealSkypeProbe;
        public bool IncludeHostCacheProbe;
        public string DatabasePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "skyserver.db");
        public string SkypeSharedXmlPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Skype", "shared.xml");
        public string SqlitePath = Environment.GetEnvironmentVariable("SKYSERVER_SQLITE");
        public string KeysDirectory = Environment.GetEnvironmentVariable("SKYSERVER_KEYS_DIR");
        public ServerCommand Command = ServerCommand.Serve;
        public string[] CommandArgs = new string[0];

        public static ServerOptions Parse(string[] args)
        {
            ServerOptions options = new ServerOptions();
            if (String.IsNullOrEmpty(options.SqlitePath))
            {
                options.SqlitePath = "sqlite3";
            }

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == "--host" && i + 1 < args.Length)
                {
                    options.AuthHost = IPAddress.Parse(args[++i]);
                    options.ApiHost = options.AuthHost;
                }
                else if (arg == "--port" && i + 1 < args.Length)
                {
                    options.AuthPort = Int32.Parse(args[++i]);
                }
                else if (arg == "--api-host" && i + 1 < args.Length)
                {
                    options.ApiHost = IPAddress.Parse(args[++i]);
                }
                else if (arg == "--api-port" && i + 1 < args.Length)
                {
                    options.ApiPort = Int32.Parse(args[++i]);
                }
                else if (arg == "--db" && i + 1 < args.Length)
                {
                    options.DatabasePath = Path.GetFullPath(args[++i]);
                }
                else if (arg == "--sqlite" && i + 1 < args.Length)
                {
                    options.SqlitePath = args[++i];
                }
                else if (arg == "--once")
                {
                    options.Once = true;
                }
                else if (arg == "--keys-dir" && i + 1 < args.Length)
                {
                    options.KeysDirectory = Path.GetFullPath(args[++i]);
                }
                else if (arg == "--check-keys")
                {
                    options.Command = ServerCommand.CheckKeys;
                }
                else if (arg == "--real-skype-probe")
                {
                    options.RealSkypeProbe = true;
                }
                else if (arg == "--include-hostcache-probe")
                {
                    options.IncludeHostCacheProbe = true;
                }
                else if (arg == "--skype-shared-xml" && i + 1 < args.Length)
                {
                    options.SkypeSharedXmlPath = Path.GetFullPath(args[++i]);
                }
                else if (arg == "--init-db")
                {
                    options.Command = ServerCommand.InitDb;
                }
                else if (arg == "--add-account" && i + 3 < args.Length)
                {
                    options.Command = ServerCommand.AddAccount;
                    options.CommandArgs = new[] { args[++i], args[++i], args[++i] };
                }
                else if (arg == "--set-email" && i + 2 < args.Length)
                {
                    options.Command = ServerCommand.SetEmail;
                    options.CommandArgs = new[] { args[++i], args[++i] };
                }
                else if (arg == "--remove-account" && i + 1 < args.Length)
                {
                    options.Command = ServerCommand.RemoveAccount;
                    options.CommandArgs = new[] { args[++i] };
                }
                else if (arg == "--add-contact" && i + 2 < args.Length)
                {
                    options.Command = ServerCommand.AddContact;
                    options.CommandArgs = new[] { args[++i], args[++i] };
                }
                else
                {
                    throw new ArgumentException("Unknown or incomplete argument: " + arg);
                }
            }

            return options;
        }
    }
}
