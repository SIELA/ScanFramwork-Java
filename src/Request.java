import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

public class Request {

	public Request(String requestfilename) {
		
		//�������ı�
		File reqfile = new File(requestfilename);
		try {
			BufferedReader br = new BufferedReader(new FileReader(reqfile));
			String line = br.readLine();
			
			//ȡ�÷�����·�����汾Ĭ��ΪHTTP/1.1
			this.method = line.split(" ")[0];
			this.path = line.split(" ")[1];
			
			//ȡ�ø���ͷ
			String trimheader = null;
			while((line = br.readLine()) != null) {
				if(line.length()<3)
					break;
				trimheader = line.replace(" ", "");
				this.headers.put(trimheader.split(":")[0], trimheader.split(trimheader.split(":")[0]+":")[1]);
			}
			
			//ȡ��POST����
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

//����ͷ
class Headers{
	String key;
	String value;
	
	public Headers(String key, String value) {
		this.key = key;
		this.value = value;
	}
}
