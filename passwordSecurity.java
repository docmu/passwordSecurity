import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Scanner;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class passwordSecurity {
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		Scanner reader = new Scanner(System.in);  
		Scanner scanUsername = new Scanner(System.in); 
		Scanner scanPassword = new Scanner(System.in); 
		boolean loop = true;
		
		while(loop) {
			System.out.println("\nChoose an option:\n1.Login\n2.Add a new username and password");
			int option = reader.nextInt(); 
			
			if(option == 1 || option == 2) {
				System.out.println("Enter username: ");
				String username = scanUsername.next();
				System.out.println("Enter your password: ");
				String password = scanPassword.next();
				
				if(option == 1) {		
					login(username, password);
				} else if(option == 2) {
					validateLoginCredentials(username, password);
				}
			}		
		}
	}
	
	//login if username and password is in passwords.txt
	public static void login(String username, String password) {
		BufferedReader br = null;
		try { 
			br = new BufferedReader(new FileReader("passwords.txt"));
			String brLine = "";
			
			while(brLine != null) {
				String user = br.readLine();
				String pass = br.readLine(); //the hashed password
				if(user == null) break; 
				String hashedSaltedInputedPassword = new String(hashAndSalt(password));
//				String hashedSaltedReadPassword = new String(hashAndSalt(pass));
				if(username.equals(user) && hashedSaltedInputedPassword.equals(pass)) {
					System.out.println(user + " has logged in successfully!");
					return;
				}
			}
			System.out.println("Login Failed!");
		} catch(Exception e) {
			e.printStackTrace();
		} finally {
			try {
				br.close();
			} catch(IOException ioe) {
				ioe.printStackTrace();
			}
		}	
	}
	
	//add new username and password to passwords.txt if it satisfies all the criterias
	public static void validateLoginCredentials(String username, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		BufferedWriter br = null;
		if(password.length() < 8 || !containsLetterAndNumber(password) || isRepetitive(password) || isCommonPassword(password)) {
			System.out.println("The password you entered is invalid, try again!");
		} else {
			try {
				File file = new File("passwords.txt");
				String hashedSaltedPassword = "";
				
				if(!file.exists()) {
					file.createNewFile();
				}
				
				FileWriter fileWriter = new FileWriter(file, true);
				br = new BufferedWriter(fileWriter);
				
				br.write(username);
				br.newLine();
				
				hashedSaltedPassword = new String(hashAndSalt(password));
				br.write(hashedSaltedPassword);
				br.newLine();
				
				System.out.println("New Username and Password Successfully Added!");
			} catch(IOException ioe) {
				ioe.printStackTrace();
			} finally {
				try {
					if (br != null){
						br.close();
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}		
	}
	
	private static byte[] hashAndSalt(String password) throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] salt = new byte[16];
	    byte[] hash = null;
	    for (int i = 0; i < 16; i++) {
	        salt[i] = (byte) i;
	    }
	    try {
	        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
	        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	        hash = f.generateSecret(spec).getEncoded();

	    } catch (NoSuchAlgorithmException nsale) {
	        nsale.printStackTrace();

	    } catch (InvalidKeySpecException ikse) {
	        ikse.printStackTrace();
	    }
		return hash;
	}
	
	//password contains at least 1 letter and 1 number
	public static boolean containsLetterAndNumber(String password){
		if(password.matches(".*\\d.*") && password.matches(".*[a-z].*")){
			return true;
		}
		return false;
	}
	//password contains sequence of 4+ consecutive/repetitive letters/numbers
	public static boolean isRepetitive(String password) {
		String[] arr = password.split("");
		int numCount = 0;
		int letterCount = 0;
		
		for(int i = 0; i < arr.length; i++) {
			if(numCount >=4 || letterCount >= 4) return true;
			if(arr[i].matches(".*\\d.*")) {
				if(letterCount != 0) {
					letterCount = 0;
				} 
				numCount++;
			} else if(arr[i].matches(".*[a-z].*")) {
				if(numCount != 0) {
					numCount = 0;
				}
				letterCount++;
			}
		}
		return false;
	}
	//top 10 most common passwords
	public static boolean isCommonPassword(String password) {
		if(password.equals("123456") || password.equals("123456789") 
				|| password.equals("qwerty") || password.equals("password") 
				|| password.equals("1234567") || password.equals("12345678") 
				|| password.equals("12345") || password.equals("iloveyou") 
				|| password.equals("111111") || password.equals("123123")) {
			return true;
		}
		return false;
	}
}
