import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VulScanner implements Callable<Boolean>{
	
	URL url;
	boolean success = false;
	Request request;
	String flag;
	
	//���߳�
	public Boolean call() {
		System.out.println("[-]Start scanning for "+this.url.getHost()+"....");
		//��������
		try {
			HttpURLConnection connection = (HttpURLConnection) this.url.openConnection();
			connection.setDoInput(true);
			connection.setDoOutput(true);
			connection.setInstanceFollowRedirects(false);
			connection.setUseCaches(false);
			connection.setConnectTimeout(20000);
			connection.setRequestMethod(request.method);
			//���ò���
			Iterator<Entry<String, String>> it = request.headers.entrySet().iterator();
			while(it.hasNext()) {
				Map.Entry<String, String> header = it.next();
				//��ѹ��
				if (header.getKey().equals("Accept-Encoding"))
					continue;
				connection.setRequestProperty(header.getKey(), header.getValue());
			}
			//HOST�����޸�
			connection.setRequestProperty("Host", this.url.getHost());
			
			//��ȡ��������
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder stringBuilder = new StringBuilder();
            
            //����ͷ����Ա�
			Iterator<Entry<String, List<String>>> rt = connection.getHeaderFields().entrySet().iterator();
			while(rt.hasNext()) {
				Entry<String, List<String>> rheader = rt.next();
				stringBuilder.append(rheader.getKey()+":"+rheader.getValue().get(0)+"\n");
			}
            
            //���ļ���Ա�
            String line = null;
            while ((line = bufferedReader.readLine()) != null) {
            	stringBuilder.append(line + "\n");
            }
            
            //����Ƿ�ɹ�
            checkFlag(stringBuilder.toString(), flag);
            
            if (this.success) {
				System.out.println("[*]"+ this.url.getHost() +" Hacked!");
			}
            else {
            	System.out.println("[*]"+ this.url.getHost() +" is not vulnable.");
            }
            //�رջ��������
            bufferedReader.close();
            connection.disconnect();
			return this.success;
		} catch (IOException e) {
			System.out.println("[!]Cannot connect to the target "+ this.url.getHost() +"!");
			return false;
		}
		
	}
	
	//ɨ��ʵʩ
	public VulScanner(String url, Request request, String flag) {
		//��ӷ���ǰ׺
		if (!url.contains("://")) {
			url = "http://"+url;
		}
		try {
			this.url = new URL(url.concat(request.path));
		} catch (MalformedURLException e) {
			System.out.println("[!]Invalid URL "+ this.url.toString() +"!");
			return;
		}
	
		this.request = request;
		this.flag = flag;
		
	}
	
	//����Ƿ���©��
	private void checkFlag(String response, String flag) {
		if (flag.startsWith("match")) {
			try {
				Pattern pattern = Pattern.compile(flag.substring(6));
				Matcher m = pattern.matcher(response);
				if (m.find()) 
					this.success = true;
			} catch (Exception e) {
				System.out.println("[!]Regex pattern wrong!");
			}
		}
	}


}
