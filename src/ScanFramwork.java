import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class ScanFramwork {
	
	private static String url;
	private static String requestfilename;
	private static String flag;
	private static String targetfilename;
	private static String outputfilename;
	

	public static void main(String[] args) {
		showLogo();
		
		if (args.length == 0) {
			System.out.println("command: -h for help");
			return;
		}
		
		for (int i=0; i<args.length; i++) {
			if (!args[i].startsWith("-")) {
				url = args[i];
			}
			else if (args[i].equals("-h")) {
				showHelp();
			}
			else if (args[i].equals("-r")) {
				requestfilename = args[++i]; 
			}
			else if (args[i].equals("-p")) {
				flag = args[++i];
			}
			else if (args[i].equals("-t")) {
				targetfilename = args[++i];
			}
			else if (args[i].equals("-o")) {
				outputfilename = args[++i];
			}
			else {
				System.out.println("[!]Invalid argument :"+args[i]+".");
				return;
			}
		}
		
		//如果缺少必要参数则提示
		if (((url == null)&&(targetfilename == null))||requestfilename == null||flag == null) {
			System.out.println("[!]Lake of arguments!");
			return;
		}
		
		//使用一个request类给多个scanner使用
		Request req =  new Request(requestfilename);
		
		//线程池
        ExecutorService pool = Executors.newCachedThreadPool();
        int successnum = 0;
		//未指定url则批量
		if (url == null) {
			File targetfile = new File(targetfilename);
			File outputfile = new File(outputfilename);

			try {
				BufferedWriter bro = new BufferedWriter(new FileWriter(outputfile));
				System.out.println("[-]Reading the targets file...");
			
				BufferedReader br = new BufferedReader(new FileReader(targetfile));
				String target;
				while((target = br.readLine()) != null) {
					if (target.length()<3) 
						continue;
			        VulScanner scanner = new VulScanner(target, req, flag);
			        Future<Boolean> future  = pool.submit(scanner);
			        while(!future.isDone()) {}
			        try {
						if (future.get()) {
							bro.write(target+"\n");
							successnum++;
							bro.flush();
						}
					} catch (InterruptedException | ExecutionException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				
				br.close();
				bro.close();
			} catch (IOException e) {
				System.out.println("[!]Targets file error!");
				return;
			}
		}
		//指定url则单扫
		else {
	        VulScanner scanner = new VulScanner(url, req, flag);
	        Future<Boolean> future  = pool.submit(scanner);
	        while(!future.isDone()) {}
	        try {
				if (future.get()) {
					successnum++;
				}
			} catch (InterruptedException | ExecutionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		//关闭线程池
		pool.shutdown();
		System.out.println("\n[.]Scan finished."+" "+successnum+" vulnable targets found.");
	}
	
	private static void showHelp() {
		System.out.println("##ScanFramwork 1.0##");
		System.out.println();
		System.out.println("Help:");
		System.out.println("\t	-r : Set the request file.");
		System.out.println("\t	-t : Set num of threads.");
		System.out.println("\t	-p : Set the string to match in the response which indicates the success.");
		System.out.println("\t	-h : Show this help.");
		System.out.println("\t	-o : Output file(only uses with -t).");
		System.out.println();
	}
	
	private static void showLogo() {
		System.out.println("");
		System.out.println("");
		System.out.println("!@#$%^&*()_!@#$%&*(*&^%$#@!@#$%^&*()(*&^%$#@#$%^&*");
		System.out.println("!@#$%^&*-----------*&^%$#@!@#$%^&*()(*&^%$#@#$%^&*");
		System.out.println("!@#$%^&*!!_!@#$%&*(*&^%$#@!@#$%^^^^^^^^^^$#@#$%^&*");
		System.out.println("!@#$%^&*!!_!@#$%&*(*&^%$#@!@#$%^^^^^^^^^^$#@#$%^&*");
		System.out.println("!@#$%^&*!!_!@#$%&*(*&^%$#@!@#$%^^^^^^^^^^$#@#$%^&*");
		System.out.println("!@#$%^&*!!_!@#$%&*(*&^%$#@!@#$%^^^^^^^^^^$#@#$%^&*");
		System.out.println("!@#$%^&*-----------*&^%$#@!@#$%^&*()(*&^%$#@#$%^&*");
		System.out.println();
		System.out.println("--ScanFramwork 1.0 .");
		System.out.println("");
	}
}
