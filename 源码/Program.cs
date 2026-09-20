using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using System.Windows.Forms;
using Microsoft.Win32;

internal static class Program {
    internal static string DataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ClearWebGuard");
    internal static string InstalledExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClearWebGuard", "ClearWebGuard.exe");
    internal static bool IsAdmin { get { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } }
    internal static string[] Domains(string text) {
        var list = text.Split(new char[]{'\r','\n',',',';',' ','\t'}, StringSplitOptions.RemoveEmptyEntries).Select(x=>x.Trim().ToLowerInvariant()).Distinct().ToArray();
        if (list.Length == 0 || list.Length > 150) throw new Exception("请输入 1–150 个域名，每行一个，不含 https:// 或路径。");
        foreach (var s in list) if (s.Length > 253 || !Regex.IsMatch(s, @"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")) throw new Exception("域名格式不正确：" + s);
        return list;
    }
    internal static string Quote(string s) { return "'" + s.Replace("'", "''") + "'"; }
    internal static string Engine(string action, string[] domains) {
        string script;
        using(var reader = new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream("engine.ps1"), Encoding.UTF8)) script = reader.ReadToEnd();
        string code = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; try { & {\n" + script + "\n} -Action " + Quote(action) + " -Domains @(" + String.Join(",", domains.Select(Quote)) + ") -SourceExe " + Quote(Application.ExecutablePath) + "; if (-not $?) { exit 1 } } catch { [Console]::Error.WriteLine($_.ToString()); exit 1 }";
        // Execute script via standard input to avoid command-length limits and writable elevated script files.
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"WindowsPowerShell\\v1.0\\powershell.exe"), "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -");
        info.UseShellExecute=false; info.CreateNoWindow=true; info.RedirectStandardInput=true; info.RedirectStandardOutput=true; info.RedirectStandardError=true;
        info.StandardOutputEncoding=Encoding.UTF8; info.StandardErrorEncoding=Encoding.UTF8;
        using(var p = Process.Start(info)) {
            var output = p.StandardOutput.ReadToEndAsync(); var error = p.StandardError.ReadToEndAsync();
            // A single encoded Invoke-Expression statement allows PowerShell's stdin mode to execute multiline code reliably.
            p.StandardInput.WriteLine("Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+Convert.ToBase64String(Encoding.UTF8.GetBytes(code))+"')))" );
            p.StandardInput.Close(); p.WaitForExit();
            string result=output.Result + error.Result;
            if(p.ExitCode!=0) throw new Exception(result);
            return result;
        }
    }
    [STAThread] static void Main(string[] args) {
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        try {
            if(args.Length>0 && args[0]=="--selftest") {
                if(Domains("MISSAV.WS\n123av.com\nmissav.ws").Length!=2) throw new Exception("dedup");
                foreach(string bad in new[]{"https://bad.com","a.com;$(whoami)","-bad.com","a..com","localhost"}) {
                    bool rejected=false; try{Domains(bad);}catch{rejected=true;} if(!rejected)throw new Exception("accepted invalid domain");
                }
                if(Quote("a'b")!="'a''b'")throw new Exception("quoting");
                File.WriteAllText(args[1],"PASS: normalization, duplicate removal, domain validation, PowerShell quoting.\r\n"+Engine("Check",new[]{"missav.ws","123av.com"}),Encoding.UTF8); return;
            }
            if(args.Length>0 && args[0]=="--worker") {
                if(!IsAdmin)throw new Exception("需要 Windows 管理员授权。");
                string action=args[1]; if(action!="Apply" && action!="Remove")throw new Exception("不支持的操作。");
                var domains=Domains(Encoding.UTF8.GetString(Convert.FromBase64String(args[2])));
                string result=Engine(action,domains);
                if(action=="Remove") {
                    string cleanup="Wait-Process -Id "+Process.GetCurrentProcess().Id+" -ErrorAction SilentlyContinue; for($attempt=0;$attempt -lt 60;$attempt++){ try { Remove-Item -LiteralPath "+Quote(InstalledExe)+" -Force -ErrorAction Stop; break } catch { Start-Sleep -Seconds 1 } }";
                    var ci=new ProcessStartInfo("powershell.exe","-NoProfile -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(cleanup)));
                    ci.UseShellExecute=false;ci.CreateNoWindow=true;Process.Start(ci);
                }
                MessageBox.Show(action=="Apply"?"防护已开启。请保存工作并重新启动浏览器。\n\n日常请使用标准账户，由可信任的人保管管理员密码。":"已撤销本程序的配置，并保留安装前已有的限制。\n程序文件将在管理窗口关闭后清理。", "清朗防护",MessageBoxButtons.OK,MessageBoxIcon.Information); return;
            }
            var form=new MainForm();
            if(args.Length>0 && args[0]=="--preview") { form.Show();Application.DoEvents();using(var b=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(b,new Rectangle(Point.Empty,b.Size));b.Save(args[1]);}form.Close();return; }
            if(args.Length>0 && args[0]=="--uninstall") form.Shown+=(s,e)=>form.RemoveProtection();
            Application.Run(form);
        } catch(Exception ex) { if(args.Length>0 && args[0]=="--selftest"){File.WriteAllText(args[1],ex.ToString());Environment.ExitCode=1;}else{MessageBox.Show(ex.Message,"清朗防护 · 操作未完成",MessageBoxButtons.OK,MessageBoxIcon.Error);Environment.ExitCode=1;} }
    }
}
internal sealed class MainForm:Form {
    TextBox domains=new TextBox(), log=new TextBox(); Label status=new Label(); Button apply,check,remove; bool busy;
    static Color Ink=Color.FromArgb(26,44,54), Teal=Color.FromArgb(0,116,105);
    public MainForm() {
        Text="清朗防护 · ClearWebGuard"; ClientSize=new Size(850,710); MinimumSize=new Size(866,749); StartPosition=FormStartPosition.CenterScreen;
        BackColor=Color.FromArgb(243,247,246); Font=new Font("Microsoft YaHei UI",10); AutoScaleMode=AutoScaleMode.Dpi;
        var top=new Panel{Dock=DockStyle.Top,Height=120,BackColor=Ink};Controls.Add(top);
        top.Controls.Add(new Label{Text="清朗防护",ForeColor=Color.White,Font=new Font(Font.FontFamily,25,FontStyle.Bold),Location=new Point(28,20),AutoSize=true});
        top.Controls.Add(new Label{Text="给专注留出空间，让访问多一道边界。",ForeColor=Color.FromArgb(191,220,211),Location=new Point(31,76),AutoSize=true});
        status.SetBounds(30,139,790,31);status.Font=new Font(Font.FontFamily,12,FontStyle.Bold);status.ForeColor=Teal;Controls.Add(status);
        AddLabel("系统 DNS 成人内容过滤  ·  指定域名拦截  ·  Chrome / Edge 策略",30,178,790,24);
        AddLabel("网站黑名单",30,222,360,25).Font=new Font(Font.FontFamily,11,FontStyle.Bold);
        AddLabel("每行一个域名；内置两个重点网站，保存时只追加。",30,253,790,25);
        domains.SetBounds(30,286,380,157);domains.Multiline=true;domains.ScrollBars=ScrollBars.Vertical;domains.BorderStyle=BorderStyle.FixedSingle;
        domains.Text="missav.ws\r\n123av.com"; string file=Path.Combine(Program.DataDir,"domains.txt");if(File.Exists(file))domains.Text=File.ReadAllText(file);Controls.Add(domains);
        var panel=new Panel{Location=new Point(438,286),Size=new Size(382,157),BackColor=Color.FromArgb(227,238,233)};Controls.Add(panel);
        panel.Controls.Add(new Label{Text="管理员保护",Location=new Point(16,13),AutoSize=true,Font=new Font(Font.FontFamily,11,FontStyle.Bold),ForeColor=Ink});
        panel.Controls.Add(new Label{Text="安装、修改和卸载都需要 Windows 管理员授权。\n\n标准账户无法删除安装目录或修改系统规则。请让可信任的人保管管理员密码。",Location=new Point(16,47),Size=new Size(350,102),ForeColor=Ink});
        apply=ButtonAt("安装 / 加固防护",30,462,190,true);apply.Click+=async(s,e)=>await Change("Apply");
        check=ButtonAt("检测当前状态",234,462,174,false);check.Click+=async(s,e)=>{SetBusy(true);try{log.Text="正在检查 DNS 和域名解析…";string[] ds=Program.Domains(domains.Text);log.Text=await System.Threading.Tasks.Task.Run(()=>Program.Engine("Check",ds));RefreshState();}catch(Exception ex){log.Text=ex.Message;}finally{SetBusy(false);}};
        remove=ButtonAt("管理员卸载",630,462,190,false);remove.Click+=(s,e)=>RemoveProtection();
        log.SetBounds(30,525,790,97);log.Multiline=true;log.ReadOnly=true;log.ScrollBars=ScrollBars.Vertical;log.BackColor=Color.White;log.Text="关闭窗口后，已安装的系统规则继续生效。首次安装会保存原配置。";Controls.Add(log);
        AddLabel("保护边界：无法保证覆盖所有网站、浏览器或网络方式；持有管理员权限的人仍可解除。\n卸载只恢复本程序安装前的配置，不会清除先前已存在的拦截。",30,641,790,50);
        RefreshState();FormClosing+=(s,e)=>{if(busy){e.Cancel=true;}};
    }
    Label AddLabel(string text,int x,int y,int w,int h){var l=new Label{Text=text,Location=new Point(x,y),Size=new Size(w,h),ForeColor=Ink};Controls.Add(l);return l;}
    Button ButtonAt(string text,int x,int y,int w,bool primary){var b=new Button{Text=text,Location=new Point(x,y),Size=new Size(w,43),FlatStyle=FlatStyle.Flat,BackColor=primary?Teal:Color.White,ForeColor=primary?Color.White:Ink};b.FlatAppearance.BorderColor=primary?Teal:Color.FromArgb(201,216,211);Controls.Add(b);return b;}
    void RefreshState(){using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ClearWebGuard")){status.Text=key==null?"尚未安装本程序 · 电脑可能已有其他拦截规则":"已安装管理员保护 · 点击检测核对实际过滤状态";remove.Enabled=key!=null;}}
    void SetBusy(bool value){busy=value;apply.Enabled=!value;check.Enabled=!value;remove.Enabled=!value;domains.Enabled=!value;UseWaitCursor=value;if(!value)RefreshState();}
    async System.Threading.Tasks.Task Change(string action){
        try{
            var ds=Program.Domains(domains.Text).Union(new[]{"missav.ws","123av.com"}).ToArray();
            string file=Path.Combine(Program.DataDir,"domains.txt");if(File.Exists(file))ds=ds.Union(Program.Domains(File.ReadAllText(file))).ToArray();
            ds=Program.Domains(String.Join("\n",ds));
            SetBusy(true);log.Text="等待 Windows 管理员授权并执行配置…";
            var pi=new ProcessStartInfo(Application.ExecutablePath,"--worker "+action+" "+Convert.ToBase64String(Encoding.UTF8.GetBytes(String.Join("\n",ds))));pi.UseShellExecute=true;pi.Verb="runas";
            bool success;
            using(var p=Process.Start(pi)){await System.Threading.Tasks.Task.Run(()=>p.WaitForExit());success=p.ExitCode==0;log.Text=success?"操作完成。可点击“检测当前状态”验证过滤；请重启浏览器加载策略。":"操作未完成，原错误已在管理员窗口显示。";}
            if(action=="Remove" && success){SetBusy(false);Close();}
        }catch(Exception ex){log.Text="操作未完成："+ex.Message;}finally{SetBusy(false);}
    }
    public async void RemoveProtection(){if(MessageBox.Show("卸载需要管理员授权，将恢复安装前的网络与浏览器设置。\n安装前已有的限制会保留。继续？","管理员卸载",MessageBoxButtons.YesNo,MessageBoxIcon.Question)==DialogResult.Yes){await Change("Remove");}}
}
