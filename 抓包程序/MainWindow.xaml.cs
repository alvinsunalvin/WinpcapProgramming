using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Collections.ObjectModel;

namespace 抓包程序
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        ObservableCollection<Packet_Info> packets = new ObservableCollection<Packet_Info>();

        bool iscapturing = true;

        public bool Iscapturing
        {
            get
            {
                return iscapturing;
            }

            set
            {
                iscapturing = value;
            }
        }

        public delegate void InsertPacket(Packet_Info p);
        public MainWindow()
        {
            InitializeComponent();
            CaptureInterface c = new CaptureInterface();
            c.ShowDialog();
            if(App.Interface_name == "")
            {
                Close();
            }
            lsPackets.ItemsSource = packets;
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            packets.Clear();
            start.IsEnabled = false;
            iscapturing = true;
            Action capture = new Action(Capture_task);
            Task t = new Task(capture);
            t.Start();
        }
        private void Capture_task()
        {
            try
            {
                IntPtr adhandle = packet_capture.InitCapture();

                int count = 0;
                int temp_sec = 0, temp_usec = 0;

                while (iscapturing)
                {
                    Packet_Info temp = packet_capture.CapturePacket(adhandle);
                    if (temp == null)
                    {
                        continue;
                    }
                    if(count == 0)
                    {
                        temp_sec = temp.tv_sec;
                        temp_usec = temp.tv_usec;
                    }
                    temp.Time = temp.tv_sec - temp_sec + (float)(temp.tv_usec - temp_usec) / 1000000;
                    temp.Number = ++count;
                    Dispatcher.BeginInvoke(new InsertPacket(packets.Add),temp);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            iscapturing = false;
            start.IsEnabled = true;
        }
    }
}
