##################################################################
#Работа с файлами.
#Задание на практику
###################################################################

#Скачайте с сайта lib.ru любой текстовый документ и сохраните
#его под именем doc.txt.
#Проверьте кодировку.
#Напишите программу, которая сделает копию данного файла и сохранит
#eе в файл doc1.txt
#Посчитайте сколько слов содержит сохраненный файл

# import string

# #Считываем первый файл, считываем в data
# file = open("doc.txt","rt",encoding="utf-8")
# data = file.read();
# file.close()

# #Записываем данные во второй
# file_2 = open("doc1.txt", "wt", encoding="utf-8")
# file_2.write(data)
# file_2.close()

# #Открываем второй для чтения, и считываем в data
# file_2 = open("doc1.txt", "rt", encoding="utf-8")
# data = file_2.read()

# #Убираем пунктуацию
# for c in string.punctuation:
#   data = data.replace(c,'')

# #Получаем список слов
# data = data.split()

# #Выводим их количество
# print(len(data))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# В файле input.txt в разнобой записаны целые числа. Напишите
# программу, которая создаст файл output.txt и запишет в него
# сумму этих чисел

# #Считаем числа из input.txt
# numbers = open("input.txt","rt",encoding="utf-8").read()

# #Получим из них список
# numbers = numbers.split()

# #Превратим их в целые числа
# numbers = list(map(int, numbers))

# #Найдем их сумму
# sum = 0

# for number in numbers:
#   sum += number

# #Выведем сумму в файл
# output = open("output.txt","wt",encoding="utf-8")
# output.write(str(sum))
# output.close()

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




