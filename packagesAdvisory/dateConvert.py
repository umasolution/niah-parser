import re
from datetime import datetime

class dateConvert():
    def __init__(self):
        pass
    
    def dateCon(self, dateStr):
        line = dateStr
        line = line.strip()
        line = re.sub('\s+', ' ', line).strip()
        dateObj = None
        if re.match(r"^\d{8}$", line):
            dateObj = datetime.strptime(line,'%Y%m%d')
        elif re.match(r"\d{1,2} [A-z]{3,50}, \d{4}", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%d %b, %Y')
        elif re.match(r"^\d{4}-\d{2}-\d{2}T00:00:00Z", line, re.IGNORECASE):
            line = re.sub('T00:00:00Z', '', line)
            dateObj = datetime.strptime(line,'%Y-%m-%d')
        elif re.match(r"^\d{4}-\d{2}-\d{2}T00:00:00", line, re.IGNORECASE):
            line = re.sub('T00:00:00', '', line)
            dateObj = datetime.strptime(line,'%Y-%m-%d')
        elif re.match(r"^\d{4}-\d{2}-\d{2}T", line, re.IGNORECASE):
            line = line.split("T")[0]
            dateObj = datetime.strptime(line,'%Y-%m-%d')
        elif re.match(r"^[a-z]{3} \d{1,2}, \d{4}", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%b %d, %Y')
        elif re.match(r"^\d{4}-[a-z]{3}-\d{1,2}", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%Y-%b-%d')
        elif re.match(r"^\d{4}-\d{1,2}-[a-z]{3}", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%Y-%d-%b')
        elif re.match(r"^[a-z]{3} \d{1,2}st", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%b %dst, %Y')
        elif re.match(r"^[a-z]{3} \d{1,2}nd", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%b %dnd, %Y')
        elif re.match(r"^[a-z]{3} \d{1,2}th", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%b %dth, %Y')
        elif re.match(r"^[a-z]{3} \d{1,2}rd", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%b %drd, %Y')
        elif re.match(r"\d{1,2} [a-z]{3,50} \d{4}", line, re.IGNORECASE):
            try:
                dateObj = datetime.strptime(line,'%d %B %Y')
            except:
                dateObj = datetime.strptime(line,'%d %b %Y')
        elif re.match(r"^\d{1,2}/", line):
            dateObj = datetime.strptime(line,'%m/%d/%Y')

        elif re.match(r"^[a-z]{3,50} \d{1,2}, \d{4}", line, re.IGNORECASE):
            dateObj = datetime.strptime(line, '%B %d, %Y')

        elif re.match(r"^\d{4}-[A-z]{3,50}-\d{1,2}", line, re.IGNORECASE):
            dateObj = datetime.strptime(line, '%Y-%B-%d')

        elif re.match(r"^[a-z]{3}", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%b %d %Y')
        elif re.match(r"^\d{1,2} [a-z]{3}", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%d %b %Y')
        elif re.match(r"^\d{4}-\d{2}-\d{2}", line, re.IGNORECASE):
            dateObj = datetime.strptime(line,'%Y-%m-%d')
        return dateObj.strftime('%Y-%m-%d')

if __name__ == "__main__":
    res = dateConvert()
    print(res.dateCon('03 Dec, 2021'))
    #res.dateCon('01/20/2021')
    
