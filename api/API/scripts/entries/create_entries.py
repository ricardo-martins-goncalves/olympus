import random
import datetime
import names
x = input('How many people do you want to create?\n')
x = int(x)
string = ""
for i in range (x):
# Mairead Elliott;	mairead@mail.com;	912345678;	1979-05-29;	Mairead's Street

  name = names.get_full_name()
  first_name = name.split()[0]
  email = f'{first_name.lower()}@email.com'
  phone = random.randint(900000000, 1000000000)
  start_date = datetime.date(1920, 1, 1)
  end_date = datetime.date(2022, 1, 1)
  time_between_dates = end_date - start_date
  days_between_dates = time_between_dates.days
  random_number_of_days = random.randrange(days_between_dates)
  birthday = start_date + datetime.timedelta(days=random_number_of_days)
  address = f'{first_name}\'s Street'
  string += name + "; "+ email + "; " + str(phone) + "; " + str(birthday) + "; " + address + '\n'

f = open(f'entries{x}.txt', "w")
f.write(string)
f.close()
