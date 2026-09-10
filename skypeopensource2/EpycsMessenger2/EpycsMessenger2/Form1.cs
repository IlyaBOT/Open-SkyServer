using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading;

namespace EpycsMessenger2
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        public static string SelectedUser;
        public static string SelectedDisplayName;
        private Form myForm2;
        private Form myForm3;
        private Form myForm4;
        private Form myForm5;
        private Form myForm6;

        public static string auth_login;
        public static string auth_pass;

        public int global_close = 0;

        public static Dictionary<string, string> dictionary =
                new Dictionary<string, string>();

        public static Dictionary<string, string> displayNames =
                new Dictionary<string, string>();

        public static string my_addr = "";


        [DllImport("skycontact4_dll.dll", EntryPoint = "skycontact", CharSet = CharSet.Ansi)]
        private static extern int EpycsGetContacts(string user, string pass);


        // search users vcards
        [DllImport("skysearch4_dll.dll", EntryPoint = "skysearch_getslots", CharSet = CharSet.Ansi)]
        private static extern int EpycsSearchSlots(int argc, string[] argv, StringBuilder myip);
        
        [DllImport("skysearch4_dll.dll", EntryPoint = "skysearch_one", CharSet = CharSet.Ansi)]
        private static extern int EpycsSearchOneVcard(string user, StringBuilder vcard, int maxlen);

        [DllImport("skysearch4_dll.dll", EntryPoint = "skysearch_many", CharSet = CharSet.Ansi)]
        private static extern int EpycsSearchManyVcards(int argc, string[] argv, StringBuilder vcard, int maxlen);
        // end of search users vcards


        // relay connect and get remote user version
        [DllImport("skyrelay4_dll.dll", EntryPoint = "skyrelay", CharSet = CharSet.Ansi)]
        private static extern int EpycsGetVersion(string myip, string remote_name, string vcard, StringBuilder output);

        public void on_login() {
            myForm2 = new Form2();
            myForm2.Owner = this;

            //setup_listbox();
            CreateMyListView();
            SetupListImages();

            //Console.SetOut(new StreamWriter("Output.txt"));
            ShowConsoleWindow();
        }

        public void do_startup() {
            myForm3 = new Form3();
            myForm3.Owner = this;

            myForm3.Show();

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            ;
            /*
            myForm3 = new Form3();
            myForm3.Owner = this;
            */

            //System.Media.SoundPlayer player = new System.Media.SoundPlayer(@".\\sound\\Skype_Connection.wav");
            //player.Play();

            // hide main form
            /*
            BeginInvoke(new MethodInvoker(delegate
            {
                Hide();
            }));
            */

            // show login form
            //myForm3.Show();

            /*
            auth_login = "notnowagainplease";
            auth_pass = "adf123";
            */

            //textBox1.Text = "themagicforyou";
            //textBox2.Text = "adf123";
        }

        
        private void UpdateOnlineList()
        {
            string user;

            foreach (ListViewItem itemLV in listView1.Items) {                
                user = UserFromItem(itemLV);
                if (dictionary.ContainsKey(user)) {
                    itemLV.ImageIndex = 1;
                } else {
                    itemLV.ImageIndex = 0;
                };
            }

        }

        private void SetupListImages() {

            ImageList imageListSmall = new ImageList();
            imageListSmall.Images.Add(Bitmap.FromFile("pics\\MySmallImage1.bmp"));
            imageListSmall.Images.Add(Bitmap.FromFile("pics\\MySmallImage2.bmp"));
        
            listView1.SmallImageList = imageListSmall;
        }

        private string UserFromItem(ListViewItem item)
        {
            if (item.Tag != null)
            {
                return item.Tag.ToString();
            }

            return item.Text;
        }

        private string DisplayFromItem(ListViewItem item)
        {
            return item.Text;
        }

        private void AddItemToList(string username) {
            AddItemToList(username, username);
        }

        private void AddItemToList(string username, string displayName) {
            if (String.IsNullOrEmpty(displayName)) {
                displayName = username;
            }

            displayNames[username] = displayName;

            ListViewItem item = new ListViewItem(displayName, 0);
            item.Tag = username;
            item.SubItems.Add(username);
            item.SubItems.Add(" ");
            listView1.Items.Add(item);
        }

        private void CreateMyListView() {
            listView1.View = View.Details;
            listView1.FullRowSelect = true;
            listView1.Sorting = SortOrder.Ascending;
            //listView1.HeaderStyle = ColumnHeaderStyle.None;

            listView1.Columns.Add("Name", 150, HorizontalAlignment.Left);
            listView1.Columns.Add("Login", 170, HorizontalAlignment.Left);
            listView1.Columns.Add("Version", -2, HorizontalAlignment.Left);
        }


        // Console Stuff
        public void ShowConsoleWindow()
        {
            var handle = GetConsoleWindow();

            if (handle == IntPtr.Zero)
            {
                AllocConsole();
                handle = GetConsoleWindow();
            }
            else
            {
                ShowWindow(handle, SW_SHOW);
            }

            int windowTop = this.Top;
            int windowLeft = this.Left;

            int windowHeight = this.Height;
            int windowWidth = this.Width;

            int xpos = windowLeft + windowWidth;
            int ypos = windowTop;

            SetWindowPos(handle, 0, xpos, ypos, 0, 0, SWP_NOSIZE);

            System.Console.WriteLine("Debug window.");
            System.Console.WriteLine("Do not close.");

        }
        public void HideConsoleWindow()
        {
            var handle = GetConsoleWindow();

            ShowWindow(handle, SW_HIDE);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AllocConsole();

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll", EntryPoint = "SetWindowPos")]
        public static extern IntPtr SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int x, int Y, int cx, int cy, int wFlags);
        
        const int SWP_NOSIZE = 0x0001;
        const int SW_HIDE = 0;
        const int SW_SHOW = 5;
        // End of Console Stuff


        
        private void setup_listbox() {
            AddItemToList("user1");
            AddItemToList("user2");
            AddItemToList("user3");
        }

        private void clear_listbox() {
            /*
            foreach (ListViewItem itemLV in listView1.Items) {
                argv[argc] = itemLV.Text;
                argc += 1;
            };
            */
            listView1.Items.Clear();
        }

        private void fill_listbox()
        {
            string[] lines;

            try {
                lines = System.IO.File.ReadAllLines(@"contacts.txt");
            } catch (Exception e) {
                richTextBox1.Text += "The file could not be read:\n";
                richTextBox1.Text += e.Message + "\n";
                return;
            }

            foreach (string line in lines) {
                string contact;
                string displayName;
                int split;

                if (line.StartsWith("p/")) {
                    continue;
                };
                if (line.StartsWith("u/+7")) {
                    continue;
                };
                if (line.StartsWith("u/")) {
                    contact = line.Substring(2);
                    displayName = contact;
                    split = contact.IndexOf("|");
                    if (split >= 0) {
                        displayName = contact.Substring(split + 1);
                        contact = contact.Substring(0, split);
                    };
                    AddItemToList(contact, displayName);
                };
            }

        }

        private void button2_Click(object sender, EventArgs e)
        {
            string contacts_file;
            string user;
            string pass;

            clear_listbox();

            contacts_file = "contacts.txt";

            user = auth_login;
            pass = auth_pass;
            if ((user.Length == 0) || (pass.Length == 0))
            {
                richTextBox1.Text += "No login data provided.\n";
                return;
            };

            try {
                List<SkyContact> contacts = SkyServerApi.GetContacts(user, pass);
                using (StreamWriter writer = new StreamWriter(contacts_file, false, Encoding.UTF8)) {
                    foreach (SkyContact contact in contacts) {
                        writer.WriteLine("u/" + contact.Login + "|" + contact.DisplayName);
                        AddItemToList(contact.Login, contact.DisplayName);
                        dictionary[contact.Login] = contact.Vcard;
                    };
                };

                richTextBox1.Text += "Load contacts successful.\n";
                UpdateOnlineList();
            } catch (Exception ex) {
                richTextBox1.Text += "Load contacts from server failed: " + ex.Message + "\n";
                if (File.Exists(contacts_file) && new System.IO.FileInfo(contacts_file).Length > 0) {
                    richTextBox1.Text += "Load contacts from cache.\n";
                    fill_listbox();
                } else {
                    richTextBox1.Text += "Load contacts failed.\n";
                };
            };


        }



        private void listView1_MouseDoubleClick(object sender, MouseEventArgs e) {

            SelectedUser = "";
            SelectedDisplayName = "";
            if (listView1.SelectedItems.Count > 0) {
                SelectedUser = UserFromItem(listView1.SelectedItems[0]);
                SelectedDisplayName = DisplayFromItem(listView1.SelectedItems[0]);
            } else {
                richTextBox1.Text += "No selected item on doubleclick\n";
                return;
            };

            richTextBox1.Text += "Creating window for chat with " + SelectedDisplayName + " (" + SelectedUser + ")\n";

            myForm2.Show();
            myForm2.Focus();

            button3.Enabled = true;
            button4.Enabled = true;

        }


        private int save_login_to_file(){
            //todo
            return 0;
        }

        private int load_login_from_file(){
            //todo
            return 0;
        }

        public int do_prepare() 
        {
            if (listView1.Items.Count == 0) {
                richTextBox1.Text += "Error, no elements in contact list\n";
                return -1;
            };

            int argc = 0;
            foreach (ListViewItem itemLV in listView1.Items) {
                argc += 1;
            };
            richTextBox1.Text += "Count: " + argc + "\n";

            my_addr = SkyServerApi.GetMyAddress(auth_login, auth_pass);
            richTextBox1.Text += "MY_ADDR: " + my_addr + "\n";

            return 1;    
        }

        public int do_prepare_for_one(string user)
        {
            //richTextBox1.Text += "Count: " + argc + "\n";
            SetTextBoxSafe("Count: 1\n");

            my_addr = SkyServerApi.GetMyAddress(auth_login, auth_pass);
            //richTextBox1.Text += "MY_ADDR: " + my_addr + "\n";
            //SetTextBoxSafe("MY_ADDR: " + my_addr + "\n");

            return 1;
        }

        public void SetTextBoxSafe(string newText)
        {
            if (richTextBox1.InvokeRequired) richTextBox1.Invoke(new Action<string>((s) => richTextBox1.Text += s), newText);
            else richTextBox1.Text += newText;

        }

        public void do_resolv(string user) {
            string vcard_str;

            SetTextBoxSafe("Start resolv for user: " + user + "\n");

            SkyContact contact = SkyServerApi.GetProfile(auth_login, auth_pass, user);
            vcard_str = contact.Vcard;
            displayNames[user] = contact.DisplayName;

            if (!dictionary.ContainsKey(user)) {
                dictionary.Add(user, vcard_str);
            } else {
                dictionary[user] = vcard_str;
            };

            //richTextBox1.Text += "Vcards loaded for user: " + user + "\n Vcards:" + vcard_str + "\n";

            SetTextBoxSafe("Vcards loaded for user: " + user + "\n Vcards:" + vcard_str + "\n");

            /*
            vcards = vcard_str.Split('\n');
            foreach (string vcard in vcards) {                
                if (vcard.IndexOf("-s0.0.0.0") >= 0) {
                    //richTextBox1.Text += "Vcard:" + vcard + "\n";
                    SetTextBoxSafe("Vcard:" + vcard + "\n");
                } else {
                    //richTextBox1.Text += "Actual Vcard: " + vcard + "\n";
                    SetTextBoxSafe("Actual Vcard: " + vcard + "\n");
                    idx = vcard.IndexOf(" - ");
                    if (idx > 0) {
                        vcard_s = vcard.Substring(idx + 3);
                        if (!dictionary.ContainsKey(user)) {
                            dictionary.Add(user, vcard_s);
                        } else {
                            //richTextBox1.Text += "Dublicate username find: " + user + "\n";
                            SetTextBoxSafe("Dublicate username find: " + user + "\n");
                            dictionary[user] = vcard_s;
                        };
                    };
                };

            };
            */


        }

        private void button3_Click(object sender, EventArgs e)
        {
            string user;
            int ret;

            richTextBox1.Text += "Users Resolv start prepare...\n";

            ret = do_prepare();
            if (ret == -1) {
                return ;
            }

            richTextBox1.Text += "Users Resolv prepare done.\n";

            foreach (ListViewItem itemLV in listView1.Items) {
                user = UserFromItem(itemLV);
                do_resolv(user);
                
                //start_thread(user);
                //UpdateOnlineList();
            };
            
            UpdateOnlineList();

            return;
        }

        private int do_prepare2() {
            int argc;
            string[] argv = new String[1000];
            int ret;
            StringBuilder myip = new StringBuilder(1000);

            argc = 2;
            argv[0] = "notnowagainnplease";
            argv[1] = "xot_iam";

            ret = EpycsSearchSlots(argc, argv, myip);

            return ret;
        }

        private void temp_test() {
            string user;

            do_prepare2();

            user = "notnowagainplease";
            do_resolv(user);
            user = "xot_iam";
            do_resolv(user);

        }

        private void dump_list() {
            List<string> list = new List<string>(dictionary.Keys);

            richTextBox1.Text += "List:\n";
            foreach (string k in list) {
                richTextBox1.Text += "[\""+k+"\"] --> " + dictionary[k] + "\n";
            };
        }

        private void check_versions() {
            string myip;
            string remote_name;
            string vcard;
            StringBuilder output = new StringBuilder(1000);
            string version;
            List<string> list = new List<string>(dictionary.Keys);

            if (my_addr.Length == 0) {
                richTextBox1.Text += "MY_ADDR unknown.\n";
                return;
            };
            myip = my_addr;

            richTextBox1.Text += "Start checking skype versions.\n";

            foreach (string k in list) {
                richTextBox1.Text += "Checking: [\"" + k + "\"] --> " + dictionary[k] + "\n";
            
                remote_name = k;
                vcard = dictionary[k];

                // clean output buffer
                output.Clear();
                //output.Length=0;

                version = "SkyServer local";
                richTextBox1.Text += "Version: " + version + "\n";

                SetContactVersion(remote_name, version);
            };


        }


        private void SetContactVersion(string user, string version) {
            foreach (ListViewItem itemLV in listView1.Items) {
                if (UserFromItem(itemLV) == user) {
                    itemLV.SubItems[2].Text = version;
                    //richTextBox1.Text += "Userinfo: " + userinfo + "\n";
                    return;
                };
            };
        }

        /*
        public void WorkThreadFunction(string user) {
            try {
                // do any background work
                do_resolv(user);
            }
            catch (Exception ex) {
                // log errors
                richTextBox1.Text += "Creating or running Thread error\n";
            }
        }
        */

        /*
        private void start_thread(string user) {
            var thread = new Thread(
                   () => WorkThreadFunction(user));
            thread.Start();
            //Thread t = new Thread(new ParameterizedThreadStart(WorkThreadFunction));
            //t.Start(user);
        }
        */

        private void button4_Click(object sender, EventArgs e)
        {
            //SetContactVersion("echo123", "1.1.1.1");
            //get_version_test();

            check_versions();

            //temp_test();
            dump_list();
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            this.global_close = 1;

            Application.Exit();
            
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e) {
            //
            //Form frmAbout = new Form();
            myForm4 = new Form4();
            myForm4.Owner = this;

            myForm4.ShowDialog();
            //myForm4.Show();

        }

        private void usageToolStripMenuItem1_Click(object sender, EventArgs e) {
            //
            //
            myForm5 = new Form5();
            myForm5.Owner = this;

            myForm5.Show();

        }

        private void advancedToolStripMenuItem_Click(object sender, EventArgs e) {
            //
            //
            myForm6 = new Form6();
            myForm6.Owner = this;

            myForm6.Show();
        }


    }
}
