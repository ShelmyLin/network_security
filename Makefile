#complier
CC = gcc

#options
OPT = -lm
OBJ = vigenere.o


all : $(OBJ)
	$(CC) $(OBJ) -o run $(OPT)

vigenere.o : vigenere.c
	$(CC) -c vigenere.c $(OPT)
clean : 
	rm $(OBJ)
