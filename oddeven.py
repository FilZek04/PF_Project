def countLetters(string) : 
    count = 0 
    for letter in string : 
        if letter.isalpha() : 
            count += 1

    if count % 2 == 0 : 
        return "No"
    return "Yes"

print (countLetters("Hello There"))
print(countLetters("1"))
print(countLetters("ujfhjsfhje872jfsj34"))
print(countLetters("abc"))