using System;
using System.Collections.Generic;
using System.Threading;
using SkyServer;

internal static class MessageStorageTests
{
    internal static void Run(string path, string sqlite)
    {
        SkyDatabase db = new SkyDatabase(path, sqlite);
        db.AddAccount("message.test", "Message Test", "test-password");
        db.AddContact("message.test", "transport.test");
        const int count = 8;
        Thread[] threads = new Thread[count];
        long[] ids = new long[count];
        Exception[] errors = new Exception[count];
        using (ManualResetEvent start = new ManualResetEvent(false))
        {
            for (int i = 0; i < count; i++)
            {
                int index = i;
                threads[i] = new Thread(delegate() {
                    try
                    {
                        start.WaitOne();
                        ids[index] = new SkyDatabase(path, sqlite).SendMessage("message.test", "transport.test", Body(index));
                    }
                    catch (Exception ex) { errors[index] = ex; }
                });
                threads[i].IsBackground = true;
                threads[i].Start();
            }
            start.Set();
            bool completed = true;
            foreach (Thread thread in threads) if (!thread.Join(15000)) completed = false;
            if (!completed) throw new Exception("Message storage workers did not finish");
        }
        List<MessageRecord> history = new SkyDatabase(path, sqlite).GetHistory("transport.test", "message.test");
        HashSet<long> unique = new HashSet<long>();
        for (int i = 0; i < count; i++)
        {
            if (errors[i] != null) throw new Exception("Concurrent message insert failed", errors[i]);
            long id = ids[i];
            MessageRecord message = history.Find(delegate(MessageRecord record) { return record.Id == id; });
            if (id <= 0 || !unique.Add(id) || message == null || message.Body != Body(i))
                throw new Exception("Returned message ID does not belong to its body");
        }
        if (db.ReceiveMessages("message.test", "transport.test").Count != 0)
            throw new Exception("Sender consumed recipient's incoming messages");
        if (db.ReceiveMessages("transport.test", "message.test").Count != count ||
            db.ReceiveMessages("transport.test", "message.test").Count != 0 ||
            new SkyDatabase(path, sqlite).GetHistory("message.test", "transport.test").Count != count)
            throw new Exception("Legacy message delivery/history persistence failed");
        Console.WriteLine("PASS message storage: concurrent IDs, Unicode/multiline bodies, recipient isolation, reopen and history. Not a native Skype chat test.");
    }

    private static string Body(int i) { return "storage-" + i + "\n\t'\u041f\u0440\u0438\u0432\u0435\u0442 \ud83d\ude00"; }
}
