using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace 抓包程序
{
    /// <summary>
    /// CaptureInterface.xaml 的交互逻辑
    /// </summary>
    public partial class CaptureInterface : Window
    {
        public CaptureInterface()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                lsInterface.ItemsSource = packet_capture.GetAllDevs();
            }
            catch(Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void lsInterface_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            ListView lv = (ListView)sender;
            App.Interface_name = ((InterfaceInfo)lv.SelectedItem).Name;
            Close();
        }
    }
}
