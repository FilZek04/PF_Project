def countLetters(string) :
    # count for how many letters there are (initialized to 0)
    count = 0
    ''' for loop to go trough each character in the string checking if its
    a letter and if it is adding 1 to the current count '''
    for letter in string :
        if letter.isalpha() :
            count += 1
    # if count is divisble by 2 (so even) return no else we return yes
    if count % 2 == 0 :
        return "No"
    return "Yes"

# test cases, wrapped as a distinct test file exists.
if __name__ == "__main__":
    print (countLetters("Hello There"))
    print(countLetters("1"))
    print(countLetters("ujfhjsfhje872jfsj34"))
    print(countLetters("abc"))
    print(countLetters(""))
    print(countLetters("AbCdEfGh"))
    print(countLetters("192.0.0.0"))
