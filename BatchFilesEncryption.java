import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;

import java.util.Random;  
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;  
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

class FileDigest 
{ 
	public static File file;

	FileDigest(String filepath)
	{
		this.file = new File(filepath);

	}
  	public static String getFileMD5() throws IOException
  	{
	    if (!file.isFile())
	    {
	      return null;
	    }
	    MessageDigest digest = null;
	    FileInputStream in=null;
	    byte buffer[] = new byte[1024];
	    int len;
	    try {
		      digest = MessageDigest.getInstance("MD5");
		      in = new FileInputStream(file);
      		  while ((len = in.read(buffer, 0, 1024)) != -1)
      		  	{
      		  		digest.update(buffer, 0, len);
      			}
      		  in.close();
	    	}catch (Exception e)
	    		{
	    			e.printStackTrace();
	    			return null;
	    		}
	    BigInteger bigInt = new BigInteger(1,digest.digest());
	    return bigInt.toString(16);
  	}
}

class SearchDir
{	
	//OperaType="encrypt" or "decrypt"	
	public static String OperaType;
	public static String PassWord;

	static JTextArea showarea;
	
	SearchDir(String opera,String pwdpath,JTextArea showarea) throws IOException
	{
		this.OperaType = opera;
		FileDigest filemd5 = new FileDigest(pwdpath);
		this.PassWord = filemd5.getFileMD5();
		this.showarea = showarea; //向GUI输出信息时使用
		showarea.setText("");
	}

	public static void search(String CurrentRootDirName,String SubDirName,String CurrentVisit)  throws IOException,NoSuchAlgorithmException,Exception
	{	
		//para CurrentVisit used to judge whether will visit a file obj
		//the reason why do so is to prepare for setting up file name after encryption
		File RootDirObj;

		
		if(CurrentVisit=="")
			RootDirObj = new File(CurrentRootDirName,SubDirName);
		else
			RootDirObj = new File(CurrentRootDirName,SubDirName+CurrentVisit);

		if(RootDirObj.canRead())
		{
			if(RootDirObj.isFile())

			{					
				ImplementAES_CBC test = new ImplementAES_CBC(RootDirObj,PassWord,CurrentRootDirName+SubDirName,showarea);
				if(OperaType=="encrypt")
				{						
					test.encrypt();
				}
				else
				{	
					test.decrypt();
				}
				//System.out.println(RootDirObj.getName()+" Path:"+(CurrentRootDirName+SubDirName));

				/*
				FileDigest a = new FileDigest();
				String res = a.getFileMD5(RootDirObj);
				System.out.println("Find file :"+RootDirObj.getName()+
					"\n"+"relative path is :"+SubDirName+
					"\n"+"file MD5 is :"+res+
					"\n"+"------------------------------------------------------");	
				*/		
			}
			else
			{			
				String[] SubDirList = RootDirObj.list();
				//目录可访问，若该目录下存在子目录，则循环递归调用自身，继续向深处		
				if(SubDirList!=null && SubDirList.length!=0)
				{
					for(int i=0;i<SubDirList.length;i++)
					{	if(SubDirList[i].contains("."))
							search(CurrentRootDirName,SubDirName+"\\",SubDirList[i]);
						else
							search(CurrentRootDirName,SubDirName+"\\"+SubDirList[i],"");
					}	
				}			
			}
		}
	}
}

class ImplementAES_CBC
{
	public File file;
	public String RandomIV;
	public String password;
	public String FileAbsolutePath;

	JTextArea showarea;

	public String GetRandomIV(int length) 
	{ 
	    String base = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&()_+=-{}[],";   
	    Random random = new Random();   
	    StringBuffer sb = new StringBuffer();   
	    for (int i = 0; i < length; i++) 
	    {   
	        int number = random.nextInt(base.length());   
	        sb.append(base.charAt(number));   
	    }   
	    return sb.toString();   
 	}

 	final String CIPHER_ALGORITHM_CBC = "AES/CBC/PKCS5Padding";
 	
 	ImplementAES_CBC(File f,String pwd,String path,JTextArea showarea)
 	{	
 		this.file = f; 		
 		this.password = pwd;
 		this.FileAbsolutePath = path;//加解密后重新创建文件时使用
 		this.showarea = showarea; //向GUI窗口输出信息时使用
 	}

	public void encrypt() throws IOException,NoSuchAlgorithmException,Exception
	{	
		//get the whole file plaintext content
		Long filelength = file.length();		
		byte[] plaintext = new byte[filelength.intValue()];
		InputStream in = new FileInputStream(file);
		in.read(plaintext);
		in.close();

		// Generate a key from password
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128,new SecureRandom(password.getBytes()));
		SecretKey key=kgen.generateKey();

		//Generate a randrom IV
		RandomIV = GetRandomIV(16);		
		IvParameterSpec IV = new IvParameterSpec(RandomIV.getBytes());

		//Encrypting
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CBC);
		cipher.init(Cipher.ENCRYPT_MODE, key, IV);
		byte[] encryption = cipher.doFinal(plaintext);
		
		showarea.append("Finished to encrypt file : "+file.getName()+"\n");
		
		//write ciphertext into new file
		OutputStream f = new FileOutputStream(FileAbsolutePath+RandomIV+"."+file.getName());
		f.write(encryption);
		f.close();

		//delele original file
		file.delete();	

	}
	
	public void decrypt() throws IOException,NoSuchAlgorithmException,Exception
	{	
		//get the whole file ciphertext content
		Long filelength = file.length();		
		byte[] ciphertext = new byte[filelength.intValue()];
		InputStream in = new FileInputStream(file);
		in.read(ciphertext);
		in.close();

		//split ciphertext file name with "."
		String[] FileName = file.getName().split("\\.");
		//deal file name when more than one "." in origial file name
		String filename = "";
		for(int i=1;i<FileName.length-1;i++)
			filename += FileName[i]+".";
		filename += FileName[FileName.length-1];

		// Generate a key
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128,new SecureRandom(password.getBytes()));
		SecretKey key=kgen.generateKey();

		//Generate a randrom IV
		RandomIV = FileName[0];
		IvParameterSpec DecIV = new IvParameterSpec(RandomIV.getBytes());

		try
		{
			//Decrypting
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CBC);
			cipher.init(Cipher.DECRYPT_MODE, key, DecIV);
			byte[] decryption = cipher.doFinal(ciphertext);

			showarea.append("Finished to decrypt file : "+file.getName()+"\n");

			OutputStream f = new FileOutputStream(FileAbsolutePath+filename);
			f.write(decryption);
			f.close();

			file.delete();

		}
		catch(BadPaddingException e)
		{	
			showarea.append("File "+"\""+file.getName()+"\""+" Decrypting Error!"+"\n");			
		}
		
		
	}
}

public class BatchFilesEncryption implements ActionListener
{	
	static final int WIDTH=450;
    static final int HEIGHT=500;
    JFrame jf = null;
    JPanel contentPane = null;
    JTextArea ShowTextArea = null;
    JScrollPane ShowArea = null;
    JTextField DirHint = null;
    JTextField KeyHint = null;
	JButton ChooseDirButton = null;
	JButton EncryptButton = null;
	JButton DecryptButton = null;
	JButton ChooseKeyButton = null;

	String OperateDir;
	String OperateType;
	String OperateKey;

	String[] ImageFileSuffix = {".jpg",".bmp",".png",".gif",".ico",".jpeg",".dwg",".tiff",".exif",".tag"};

  	private static void addComponent(	Container container, 
  										Component component,
  										int gridx, int gridy,
  										int gridwidth, int gridheight,
  										int weightx , int weighty, 
  										int anchor, int fill,
  										int top, int left,
  										int bottom , int right,
  										int ipadx , int ipady)
    {	/*************************参数说明*************************/
    	//gridx,gridy：设置组件所处行与列的起始坐标。例如gridx=0,gridy=0表示将组件放置在0行0列单元格内
    	//gridwidth,gridheight：设置组件横向与纵向的单元格跨越个数。
    	//weightx,weighty：设置窗口变大时的缩放比例,为0,1间数
    	//anchor：设置组件超过单元格大小时的对齐方式
    	//fill：  设置组件未能填满单元格大小时的对齐方式
    	//insets：设置单元格的间距。Insets(int top,int left,int bottom,int right)
    	//ipadx,ipady：设置单元格内组件的尺寸像素，若一个组件的尺寸为30*10像素，ipadx=2,ipady=3

    	Insets insets = new Insets(top,left,bottom,right);
    	GridBagConstraints gbc = new GridBagConstraints(gridx, gridy, gridwidth, gridheight, weightx, weighty, anchor, fill, insets, ipadx, ipady);//建立网格包对象
    	container.add(component, gbc);//添加到容器中
  	}
  	BatchFilesEncryption()
  	{
  		//设置顶层组件
		jf = new JFrame("批量文件加解密");
		jf.setSize(WIDTH,HEIGHT);
		jf.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		
		//创建面板容器,设置布局模式
		contentPane=new JPanel();		
		jf.setContentPane(contentPane);
		contentPane.setLayout(new GridBagLayout());
		
		//创建组件
		ShowTextArea = new JTextArea(10,10);
		ShowTextArea.setFont(new Font("标楷体", Font.BOLD, 16)); 
		ShowArea = new JScrollPane(ShowTextArea);
		ChooseDirButton = new JButton("选择待操作文件夹");
		EncryptButton = new JButton("加密");
		DecryptButton = new JButton("解密");
		ChooseKeyButton = new JButton("选择图片密钥文件");
		
		DirHint = new JTextField(20);
		DirHint.setFont(new Font("标楷体", Font.BOLD, 16));
		KeyHint = new JTextField(20);
		KeyHint.setFont(new Font("标楷体", Font.BOLD, 16));

		JPanel DirHintShow = new JPanel();
		JLabel DirHintLabel = new JLabel("已选中文件为:");
		DirHintLabel.setFont(new Font("谐体",Font.BOLD|Font.ITALIC,16));
		DirHintShow.add(DirHintLabel);
		DirHintShow.add(DirHint);

		JPanel KeyHintShow = new JPanel();
		JLabel KeyHintLabel = new JLabel("已选中密钥为:");
		KeyHintLabel.setFont(new Font("谐体",Font.BOLD|Font.ITALIC,16));
		KeyHintShow.add(KeyHintLabel);
		KeyHintShow.add(KeyHint);

		//对组件进行布局
		addComponent(jf, ShowArea, 0, 0, 3, 10, 1,1,GridBagConstraints.CENTER, GridBagConstraints.BOTH,0,0,0,0,275,275);
		addComponent(jf, DirHintShow, 0, 10, 3, 1, 1,1,GridBagConstraints.CENTER, GridBagConstraints.BOTH,0,1,1,0,1,1);
		addComponent(jf, KeyHintShow, 0, 11, 3, 1, 1,1,GridBagConstraints.CENTER, GridBagConstraints.BOTH,0,1,1,0,1,1);
		addComponent(jf, ChooseDirButton, 0, 12, 1, 2, 1,1,GridBagConstraints.CENTER, GridBagConstraints.BOTH,0,1,1,0,1,1);
		addComponent(jf, EncryptButton, 1, 12, 1, 1,1,1,GridBagConstraints.CENTER, GridBagConstraints.BOTH,0,1,0,1,1,1);
		addComponent(jf, DecryptButton, 1, 13, 1, 1,1,1,GridBagConstraints.CENTER, GridBagConstraints.BOTH,1,1,1,1,1,1);
		addComponent(jf, ChooseKeyButton, 2, 12, 1, 2,1,1,GridBagConstraints.CENTER, GridBagConstraints.BOTH,0,0,1,1,1,1);

		//将按钮们加入事件监听		
		ChooseDirButton.addActionListener(this);
		EncryptButton.addActionListener(this);
		DecryptButton.addActionListener(this);
		ChooseKeyButton.addActionListener(this);

		jf.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });

        jf.setVisible(true);
  	}
  	public void actionPerformed(ActionEvent e)
    {	
    	File file = null;
        int result;

    	if (e.getActionCommand().equals("选择待操作文件夹"))
    	{	
    		JFileChooser fileChooser = new JFileChooser();
    		fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
    		fileChooser.setApproveButtonText("确定");
            fileChooser.setDialogTitle("选择文件夹");

            result = fileChooser.showOpenDialog(jf);            
            if (result == JFileChooser.APPROVE_OPTION)
            {
                file = fileChooser.getSelectedFile();
                OperateDir = file.getAbsolutePath();
                //ShowTextArea.setText("您选择的文件夹路径为："+OperateDir);
                DirHint.setText(OperateDir);
                 
            }
            else if(result == JFileChooser.CANCEL_OPTION)
            {
                ShowTextArea.setText("您没有选择任何文件");
            }
    	}

    	if (e.getActionCommand().equals("选择图片密钥文件"))
    	{	
    		OperateKey = null; //每次重新选择密钥时都将之前选择的记录清空	
    		JFileChooser fileChooser = new JFileChooser();
    		fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
    		fileChooser.setApproveButtonText("确定");
            fileChooser.setDialogTitle("选择图片密钥文件");

            result = fileChooser.showOpenDialog(jf);            
            if (result == JFileChooser.APPROVE_OPTION)
            {
                file = fileChooser.getSelectedFile();
                for(int i=0;i<ImageFileSuffix.length;i++)
                {
                	if(file.getName().contains(ImageFileSuffix[i]))
                	{
	        			OperateKey = file.getAbsolutePath();
	        			KeyHint.setText(OperateKey);
	        			break;
                	}
                	KeyHint.setText("错误！请选择图片文件");
                }                   
            }
            else if(result == JFileChooser.CANCEL_OPTION)
            {
                ShowTextArea.setText("您没有选择任何文件");
            }
        }
    	

    	if(e.getActionCommand().equals("加密"))
    	{	
    		OperateType="encrypt";
    		if( (OperateDir!=null &&OperateDir!="") && (OperateKey!=null&&OperateKey!="") )
    		{	try
    			{
	    			SearchDir se = new SearchDir(OperateType,OperateKey,ShowTextArea);
	    			se.search(OperateDir,"","");
    			}
    			catch(Exception i)
    			{}
    		}
    		else
    		{
    			ShowTextArea.setText("请先选择好待操作文件夹和密钥文件");
    		}


    	}
    	if(e.getActionCommand().equals("解密"))
    	{
    		OperateType="decrypt";
    		if( (OperateDir!=null &&OperateDir!="") && (OperateKey!=null&&OperateKey!="") )
    		{	
    			try
    			{
	    			SearchDir se = new SearchDir(OperateType,OperateKey,ShowTextArea);
	    			se.search(OperateDir,"","");
	    		}
	    		catch (Exception i) 
	    		{}
    		}
    		else
    		{
    			ShowTextArea.setText("请先选择好待操作文件夹和密钥文件");
    		}
    	}
    }

	public static void main(String[] args) throws IOException,NoSuchAlgorithmException,Exception
	{	
		/*SearchDir se = new SearchDir("decrypt","c:/x.jpg");
		se.search("d:\\test","","");*/
		new BatchFilesEncryption();
	}
}