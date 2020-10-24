using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net.NetworkInformation;
using System.Diagnostics;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using System.IO;
using System.Xml.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;

namespace wired8021xconfigurator
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            populateInterfaceComboBox();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Close();
        }

        public string GetResourceTextFile(string filename)
        {
            string result = string.Empty;
            
            //using (Stream stream = this.GetType().Assembly.
            //           GetManifestResourceStream("wired8021xconfigurator.Resources." + filename))
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(GetType(), filename))
            using (StreamReader sr = new StreamReader(stream))
            {
                result = sr.ReadToEnd();
            }
            return result;
        }

        private void populateInterfaceComboBox()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    this.interfaceComboBox.Items.Add(nic.Name);
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            var interfaceName = this.interfaceComboBox.GetItemText(this.interfaceComboBox.SelectedItem);
            var login = this.loginBox.Text;
            var password = this.passwordBox.Text;

            enableService();
            //addCertificate();
            enable8021X(interfaceName);
            setCredentials(interfaceName, login, password);
            restartInterface(interfaceName);
            MessageBox.Show("Interface configured. You can now close this application.");
        }

        private void enableService()
        {
            var svc = new ServiceController("dot3svc");
            ServiceHelper.ChangeStartMode(svc, ServiceStartMode.Automatic);

            if (svc.Status != ServiceControllerStatus.Running)
            {
                svc.Start();
            }
        }

        private void addCertificate()
        {
            byte[] bytes;
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(GetType(), "eclair.der"))
            {
                bytes = new byte[stream.Length];
                stream.Read(bytes, 0, bytes.Length);
            }
            var cert = new X509Certificate2(bytes);

            /*
            //https://stackoverflow.com/questions/12337721/how-to-programmatically-install-a-certificate-using-c-sharp
            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
            store.Close();
            */
        }

        private void enable8021X(string interfaceName)
        {
            var tempPath = Path.GetTempFileName();
            string config_8021x = GetResourceTextFile("Wired-WinPE-PEAP-MSChapv2.xml");

            using (StreamWriter sw = new StreamWriter(tempPath))
            {
                sw.Write(config_8021x);
            }

            Process p1 = new Process();
            p1.StartInfo.FileName = "netsh";
            p1.StartInfo.Arguments = "lan add profile filename=\"" + tempPath + "\" interface=\"" + interfaceName + "\"";
            p1.StartInfo.UseShellExecute = false;
            p1.StartInfo.CreateNoWindow = true;
            //p1.StartInfo.RedirectStandardOutput = true;
            p1.Start();
            p1.WaitForExit(5000); //wait up to 5 secs

            File.Delete(tempPath);
        }

        private void setCredentials(string interfaceName, string username, string password)
        {
            var tempPath = Path.GetTempFileName();
            string config_eapuserinfo = GetResourceTextFile("eap_user_info.xml");

            //change login and password
            XDocument doc = XDocument.Parse(config_eapuserinfo);
            XNamespace ns = "http://www.microsoft.com/provisioning/MsChapV2UserPropertiesV1";
            doc.Descendants(ns + "Username").First().SetValue(username);
            doc.Descendants(ns + "Password").First().SetValue(password);
            doc.Descendants(ns + "LogonDomain").First().SetValue(""); //what do we put here?

            doc.Save(tempPath);

            Process p1 = new Process();
            p1.StartInfo.FileName = "netsh";
            p1.StartInfo.Arguments = "lan set eapuserdata filename=\"" + tempPath + "\" allusers=yes interface=\"" + interfaceName + "\"";
            p1.StartInfo.UseShellExecute = false;
            p1.StartInfo.CreateNoWindow = true;
            //p1.StartInfo.RedirectStandardOutput = true;
            p1.Start();
            p1.WaitForExit(5000); //wait up to 5 secs

            File.Delete(tempPath);
        }

        private void restartInterface(string interfaceName)
        {
            //use http://blog.opennetcf.com/2008/06/24/disableenable-network-connections-under-vista/ ?
            Process p1 = new Process();
            p1.StartInfo.FileName = "netsh";
            p1.StartInfo.Arguments = "lan reconnect interface=\"" + interfaceName + "\"";
            p1.StartInfo.UseShellExecute = false;
            p1.StartInfo.CreateNoWindow = true;
            //p1.StartInfo.RedirectStandardOutput = true;
            p1.Start();
            p1.WaitForExit(5000); //wait up to 5 secs
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            this.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        }
    }

    public static class ServiceHelper
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean ChangeServiceConfig(
            IntPtr hService,
            UInt32 nServiceType,
            UInt32 nStartType,
            UInt32 nErrorControl,
            String lpBinaryPathName,
            String lpLoadOrderGroup,
            IntPtr lpdwTagId,
            [In] char[] lpDependencies,
            String lpServiceStartName,
            String lpPassword,
            String lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(
            IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(
            string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")]
        public static extern int CloseServiceHandle(IntPtr hSCObject);

        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SERVICE_QUERY_CONFIG = 0x00000001;
        private const uint SERVICE_CHANGE_CONFIG = 0x00000002;
        private const uint SC_MANAGER_ALL_ACCESS = 0x000F003F;

        public static void ChangeStartMode(ServiceController svc, ServiceStartMode mode)
        {
            var scManagerHandle = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (scManagerHandle == IntPtr.Zero)
            {
                throw new ExternalException("Open Service Manager Error");
            }

            var serviceHandle = OpenService(
                scManagerHandle,
                svc.ServiceName,
                SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);

            if (serviceHandle == IntPtr.Zero)
            {
                throw new ExternalException("Open Service Error");
            }

            var result = ChangeServiceConfig(
                serviceHandle,
                SERVICE_NO_CHANGE,
                (uint)mode,
                SERVICE_NO_CHANGE,
                null,
                null,
                IntPtr.Zero,
                null,
                null,
                null,
                null);

            if (result == false)
            {
                int nError = Marshal.GetLastWin32Error();
                var win32Exception = new Win32Exception(nError);
                throw new ExternalException("Could not change service start type: "
                    + win32Exception.Message);
            }

            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scManagerHandle);
        }
    }
}