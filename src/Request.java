import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

public class Request {

	public Request(String requestfilename) {
		
		//处理报文文本
		File reqfile = new File(requestfilename);
		try {
			BufferedReader br = new BufferedReader(new FileReader(reqfile));
			String line = br.readLine();
			
			//取得方法和路径，版本默认为HTTP/1.1
			this.method = line.split(" ")[0];
			this.path = line.split(" ")[1];
			
			//取得各种头
			String trimheader = null;
			while((line = br.readLine()) != null) {
				if(line.length()<3)
					break;
				trimheader = line.replace(" ", "");
				this.headers.put(trimheader.split(":")[0], trimheader.split(trimheader.split(":")[0]+":")[1]);
			}
			
			//取得POST内容
			while((line = br.readLine()) != null) {
				if (line.equals("*PAYLOAD*\n")) {
					break;
				}
				this.requestbody += line;
			}
			
			this.payload = br.readLine();
			
			br.close();
			
		} catch (Exception e) {
			System.out.println("[!]Request file invailed!");
			e.printStackTrace();
			return;
		}
	}
	
	String method;
	String path;
	String requestbody = "";
	String payload = "";
	Map<String, String> headers = new HashMap<>();
	
}

//请求头
class Headers{
	String key;
	String value;
	
	public Headers(String key, String value) {
		this.key = key;
		this.value = value;
	}
}
