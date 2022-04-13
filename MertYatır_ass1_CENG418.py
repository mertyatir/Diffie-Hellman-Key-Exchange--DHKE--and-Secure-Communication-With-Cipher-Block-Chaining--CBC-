# The pseudocode
# Input: n > 2, an odd integer to be tested for primality;
#        k, a parameter that determines the accuracy of the test
# Output: composite if n is composite, otherwise probably prime
# write n − 1 as 2**s·d with d odd by factoring powers of 2 from n − 1
# LOOP: repeat k times:
#    pick a randomly in the range [2, n − 1]
#    x ← a**d mod n
#    if x = 1 or x = n − 1 then do next LOOP
#    repeat s − 1 times:
#       x ← x**2 mod n
#       if x = 1 then return composite
#       if x = n − 1 then do next LOOP
#    return composite
# return probably prime



import random
 
def is_Prime(n):
    """
    Miller-Rabin primality test.
 
    A return value of False means n is certainly not prime. A return value of
    True means n is very likely a prime.
    """
    if n!=int(n):
        return False
    n=int(n)
    #Miller-Rabin test for prime
    if n==0 or n==1 or n==4 or n==6 or n==8 or n==9:
        return False
 
    if n==2 or n==3 or n==5 or n==7:
        return True
    s = 0
    d = n-1
    while d%2==0:
        d>>=1
        s+=1
    assert(2**s * d == n-1)
 
    def trial_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True  
 
    for i in range(8):#number of trials 
        a = random.randrange(2, n)
        if trial_composite(a):
            return False
 
    return True  


# The pseudocode
# - Let q1, q2, …, qn be the prime factors of (p-1)
# 1 - Find g(p-1)/q (mod p) for all values of q = q1, q2, …, qn
# 2 - g is a generator if values do not equal 1 for any values of q. Otherwise, it is
# not.


def is_Generator(p,g):
    if(is_Prime(p)==False):
        print("p is not prime")
        return False
    
    q=[]
    
    for i in range(p):
        if(is_Prime(i) and (p-1)%i==0):
            
            q.append(i)
    
    for i in range(len(q)):
        if(((g**((p-1)/q[i]))%p)==1):
            return False
    return True


def is_Generator_test(p,g):
    list1=[]
    for a in range(p-1):
        list1.append(power(g,a,p))
    list1.sort()
    print(is_Generator(p, g))
    print(list1)
        


# the repeated squaring method

def power(base,exp,mod):
    bin_exp=bin(exp)
    reverse_bin_exp = bin_exp[-1:1:-1]
    result=1
    for i in  range(len(reverse_bin_exp)):
        if(int(reverse_bin_exp[i],2)==1):
            result=((result)* ((base**(2**i))))%mod
    return result%mod
        
    
#ElGamal public key 
#x is the selected ElGamal private key
def generate_public_key(p,g,x):
    
    if(is_Prime(p)==False):
        print("p is not prime")
        return
    if(is_Generator(p, g)==False):
        print("p is a prime but g is not a generator of p")
        return
    
    return power(g,x,p) # The public key y is g raised to the power of the private key x modulo p 






# Diffie Hellman key exchange algorithm


def key_exchange(p,g,a,b):
    
    if((0<a<p)==False):
        print("private key of Alice is not in 1<a<p-1")
        return
    
    if((0<b<p)==False):
        print("private key of Bob is not in 1<b<p-1")
        return
    
    
    alice_public_key= generate_public_key(p,g,a)
    
    if((alice_public_key is None)):
        return
    

    bob_public_key= generate_public_key(p,g,b)
    
    if((alice_public_key is None) or  bob_public_key is None):
        return

    alice_shared_secret= power(bob_public_key,a,p)
    bob_shared_secret= power(alice_public_key,b,p)
    if(alice_shared_secret==bob_shared_secret):
        print("Alice's common key= "+str(alice_shared_secret))
        print("Bob's common key= "+str(bob_shared_secret))
        return alice_shared_secret
    else:
        print("Shared secrets are not the same.")
    




#Caesar's cypher

def encrypt_char(char, key):
    return chr(ord('A') + (ord(char) - ord('A') + key) % 256)


def decrypt_char(char, key):
    return chr(ord('A') + (ord(char) - ord('A') + 256 - key) % 256)



def toUnicode(char):
    return  ord(char)




#Cipher Block Chaining using Caesar's cipher

def CBC_ENCRYPT(plaintext, key, IV):
    new_vector=IV
    cipher=[]
    for i in range(len(plaintext)):
        Pi=plaintext[i]
        Pi_bin=toUnicode(Pi)
        to_be_encrypted=Pi_bin^ new_vector   #Bitwise XOR	x ^ y 
        Ci= encrypt_char(chr(to_be_encrypted% 256), key)
        cipher.append(Ci)
       
        
        print(str(Pi)+" is encrypted as "+str(Ci)+ " using common key "+str(key)+" and vector "+str(new_vector))
        
        new_vector=toUnicode(Ci)
        
    return ''.join(cipher)


def CBC_DECRYPT(ciphertext, key, IV):
    new_vector=IV
    plaintext=[]
    for i in range(len(ciphertext)):
        Ci=ciphertext[i]
        Ci_bin=toUnicode(Ci)
        to_be_XORed=toUnicode(decrypt_char(Ci, key))
        Pi_bin=to_be_XORed ^ new_vector  #Bitwise XOR	x ^ y
        
        plaintext.append(chr(Pi_bin% 256))
        
        
        print(str(Ci)+" is decrypted as "+str(chr(Pi_bin% 256))+ " using common key "+str(key)+" and vector "+str(new_vector))
        
        new_vector=Ci_bin
        
        
    return ''.join(plaintext)


    
#Test if CBC encryption/decryption working correctly

def CBC_test(plaintext, key, IV):
    return(plaintext== CBC_DECRYPT(CBC_ENCRYPT(plaintext, key, IV), key, IV))



#Test if given message has unsupported characters. This program only supports first 256 unicode characters. 

def check_message(message):
    for char in message:
        if((0<toUnicode(char)<256)==False):
            print("Unsuported character in message. You can only use !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~")
            return False













#GUI starts from here.



p = int(input("Enter p\n"))


while(is_Prime(p)==False):
    print("value you have entered is not a prime number")
    p = int(input("Enter p\n"))
    
    
g = int(input("Enter g\n"))

while(is_Generator(p,g)==False):
    print("value you have entered is not a generetor of p="+str(p))
    g = int(input("Enter g\n"))


    
    
a = int(input("Enter Alice's secret key a \n"))


while((0<a<p)==False):
    print("Alice's secret key a must be in 0<a<"+str(p))
    a = int(input("Enter Alice's secret key a \n"))
    
    
b = int(input("Enter Bob's secret key b \n"))

while((0<b<p)==False):
    print("Bob's secret key b must be in 0<b<"+str(p))
    b = int(input("Enter Bob's secret key b \n"))
    
    
    
    
    
common_key= key_exchange(p,g,a,b)
    
IV= random.getrandbits(8)

print("Initialisation Vector is randomly generated as IV= "+ str(IV))

plaintext= str(input("Enter the message to be encrypted\n"))


while(check_message(plaintext)==False):
    plaintext= str(input("Enter the message to be encrypted\n"))
    
    
cipher= CBC_ENCRYPT(plaintext, common_key, IV)
    

print(str(plaintext)+ " is encryted as "+str(cipher))




    
decrypted=CBC_DECRYPT(cipher, common_key, IV)

print(str(cipher)+ " is decryted as "+str(decrypted))
    
    
