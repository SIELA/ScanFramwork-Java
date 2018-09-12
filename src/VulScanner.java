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
	
	//多线程
	public Boolean call() {
		System.out.println("[-]Start scanning for "+this.url.getHost()+"....");
		//建立连接
		try {
			HttpURLConnection connection = (HttpURLConnection) this.url.openConnection();
			connection.setDoInput(true);
			connection.setDoOutput(true);
			connection.setInstanceFollowRedirects(false);
			connection.setUseCaches(false);
			connection.setConnectTimeout(20000);
			connection.setRequestMethod(request.method);
			//设置参数
			Iterator<Entry<String, String>> it = request.headers.entrySet().iterator();
			while(it.hasNext()) {
				Map.Entry<String, String> header = it.next();
				//不压缩
				if (header.getKey().equals("Accept-Encoding"))
					continue;
				connection.setRequestProperty(header.getKey(), header.getValue());
			}
			//HOST单独修改
			connection.setRequestProperty("Host", this.url.getHost());
			
			//读取返回数据
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder stringBuilder = new StringBuilder();
            
            //返回头加入对比
			Iterator<Entry<String, List<String>>> rt = connection.getHeaderFields().entrySet().iterator();
			while(rt.hasNext()) {
				Entry<String, List<String>> rheader = rt.next();
				stringBuilder.append(rheader.getKey()+":"+rheader.getValue().get(0)+"\n");
			}
            
            //正文加入对比
            String line = null;
            while ((line = bufferedReader.readLine()) != null) {
            	stringBuilder.append(line + "\n");
            }
            
            //检查是否成功
            checkFlag(stringBuilder.toString(), flag);
            
            if (this.success) {
				System.out.println("[*]"+ this.url.getHost() +" Hacked!");
			}
            else {
            	System.out.println("[*]"+ this.url.getHost() +" is not vulnable.");
            }
            //关闭缓存和连接
            bufferedReader.close();
            connection.disconnect();
			return this.success;
		} catch (IOException e) {
			System.out.println("[!]Cannot connect to the target "+ this.url.getHost() +"!");
			return false;
		}
		
	}
	
	//扫描实施
	public VulScanner(String url, Request request, String flag) {
		//添加服务前缀
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
	
	//检查是否有漏洞
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
