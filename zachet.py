import netifaces, socket
from pythonping import ping

def fn_translate_SubnetToPrefix(netmask):
  """ Дополнительная функция, которая
  преобразует маску подсети ipv4 в сетевой префикс """
  
  #Разделяем айпишник в список из октетов
  binary_presentation = netmask.split('.')

  #Каждый из октетов преобразуем в целое число
  binary_presentation = list(map(int,binary_presentation))
  
  #Целое число преобразуем в двоичное, можно было так же map
  for octet in range(len(binary_presentation)):
    binary_presentation[octet] = bin(binary_presentation[octet])

  #Склеиваем все обратно
  binary_presentation = ''.join(binary_presentation)

  #Считаем количество единиц, и получаем сетевой префикс
  net_prefix = binary_presentation.count('1')

  return net_prefix
  


def fn_ipaddresses():
  #Получим список локальных интерфейсов
  interfaces = netifaces.interfaces()
  #Создадим заготовку для словаря
  if_dict = {'ipv4':[],'ipv6':[]}

  #Пройдемся по списку интерфейсов
  for interf in interfaces:
    #Получим конкретный интерфейс
    interface_info = netifaces.ifaddresses(interf)

    #Здесь будем хранить ip адреса
    ipv4_addr = interface_info[2][0]['addr']
    ipv6_addr = interface_info[23][0]['addr']

    #А здесь - маску подсети
    ipv4_netmask = interface_info[2][0]['netmask']
    
    #Чтобы получить префикс подсети для ipv6, достаточно взять значение после слэша
    ipv6_netmask = interface_info[23][0]['netmask'].split('/')
    ipv6_prefix = int(ipv6_netmask[1])

    #Добавляем в словарь адрес интерфейса и префикс
    if_dict['ipv4'].append((ipv4_addr,fn_translate_SubnetToPrefix(ipv4_netmask)))
    if_dict['ipv6'].append((ipv6_addr,ipv6_prefix))

  return if_dict


def fn_portscan(if_dict):
  #Получим список ipv4 адресов, которые будем использовать для создания сокета
  ip_list = []

  for i in range(len(if_dict['ipv4'])):
    ip_list.append(if_dict['ipv4'][i][0])

  #Создадим пустые списки для открытых и закрытых портов
  open_ports = []
  closed_ports = []

  #Создадим файлы с портами, а если они уже существуют - очистим их
  open_ports_file = open("open_ports.txt","w",encoding="utf-8")
  closed_ports_file = open("closed_ports.txt","w",encoding="utf-8")
  open_ports_file.close()
  closed_ports_file.close()

  for ip in ip_list:
    #Для каждого из айпи адресов в списке будет формироваться новый список портов
    open_ports.clear()
    closed_ports.clear()

    #Попытаемся установить соедиение в пределах 65535 портов
    for i in range(65535):
      mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      mysock.settimeout(0.5)

      try:
        my_sock.connect((ip,i))
      except:
        closed_ports.append(i) #Если порт закрыт - добавляем в список закрытых
      else:
        open_ports.append(i) #Иначе - добавляем в список открытых
        mysock.close() #И закрываем соединение

    #Добавим информацию о портах в файлы
    open_ports_file = open("open_ports.txt","a",encoding="utf-8")
    open_ports_file.writelines(f"IP-адрес: {ip}, порты: {open_ports} \n")
    open_ports_file.close()

    closed_ports_file = open("closed_ports.txt","a",encoding="utf-8")
    closed_ports_file.writelines(f"IP-адрес: {ip}, порты: {closed_ports} \n")
    closed_ports_file.close()

def fn_ipaccess(ip_list):
  #Создадим списки доступных и недоступных адресов
  up_list = []
  down_list = []

  #Для каждого IP из списка на проверку (аргумента функции) попробуем получить ответ
  for ip in ip_list:
    response = ping(ip, size=40, count=4)
    if response.success() == True: #Если ICMP-запрос прошел успешно - добавляем IP в список доступных адресов
      up_list.append(ip)
    else:
      down_list.append(ip) #Иначе - в список недоступных

  return (up_list,down_list)

#Если данный модуль является основным:
if __name__ == "__main__":
    import tabulate

    print(tabulate.tabulate(fn_ipaddresses(),headers='keys',tablefmt='grid',stralign='center'))

    #Выводим сообщение о том, что выполняется сканирование, чтобы пользователь не пугался
    print("Выполняем сканирование портов...")
    fn_portscan(fn_ipaddresses())
    print("Данные о портах находятся в файлах open_ports.txt и closed_ports.txt")
    #Попробуем открыть файлы в потоке, и считать количество строк
    try:
      with open("open_ports.txt") as fl:
        op_count = len(fl.readlines())
      with open("closed_ports.txt") as fl:
        cp_count = len(fl.readlines())
    except:
      print("Что-то пошло не так")
    else:
      print(f"В файле с открытыми портами {op_count} строк, в файле с закрытыми портами {cp_count} строк.")
    
    #Так как в ТЗ не указано, какой список проверять, возьмем этот
    ip_test_list = ['8.8.8.8','127.0.0.1','10.0.0.1','192.168.0.1']
    
    print("Проверяем доступность IP-адресов...")
    result_ip_list = fn_ipaccess(ip_test_list)

    #Для корректного отображения таблицы создадим словарь
    print(tabulate.tabulate({"Доступные": result_ip_list[0],"Недоступные": result_ip_list[1]},headers='keys',tablefmt='grid',stralign='center'))

  