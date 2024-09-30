import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;

import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TFramedTransport;

public class Client {
	public static void main(String [] args) {
		if (args.length != 3) {
			System.err.println("Usage: java Client FE_host FE_port password");
			System.exit(-1);
		}

		int threadNum = 4;
		int passwords = 4;
		int requests = 100;
		final CyclicBarrier gate = new CyclicBarrier(threadNum + 1);

		try {
			Thread[] clients = new Thread[threadNum];
			for (int i = 0; i < threadNum; ++i) {
				clients[i] = new Thread(new threadedClient(gate, passwords, args[1], requests));
				clients[i].start();
			}

			TimeUnit.SECONDS.sleep(1);
			gate.await();
			long startTime = System.currentTimeMillis();
			for (int i = 0; i < threadNum; ++i) {
				clients[i].join();
			}
			long endTime = System.currentTimeMillis();
			System.out.println(threadNum*passwords*requests * 1000f / (endTime - startTime));
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}

class threadedClient extends Thread
{
	CyclicBarrier gate;
	int port;
	int passwords;
	int requests;
	threadedClient(CyclicBarrier gate, int passwords, String port, int requests)
	{
		this.gate = gate;
		this.passwords = passwords;
		this.port = Integer.parseInt(port);
		this.requests = requests;
	}

	public void run()
	{
		List<String> password = new ArrayList<>();
		for (int i = 0; i < passwords; ++i) {
			password.add(i + "�w6!+t[`��D�������H���ĺ��E-z�5X�|z�W�V���4Թ��f�@o{��~��{��~ڴ�#H���?�20��{f�/Se�5���[*����m���J����~���Ю����dXhuK�b�BT3�N�C��q�5<),��a*�E��s�d7�x�����ps��+{i�*���e@�L��+���'�L~,j́1L�Zb��9��ީ��@�g�'���)T��]*_˩ҰbW����RYf��WN٣��R�����R�D��<�ALL�d 8���:eg>��x?6Z��Db����T&�uX陋��(b(��%�`_EB�SSK����ګ����lxj�D�($Z�qر�����D�w��9��YWͥ����.Vf���,��Kˣ��Fy�9G�����G����4�r�p�t��P{��&q�U��Rb�Uͦ�L,Е�垒�#��]t,��`G��^��N����X iG�I�M��o�L�V8�!7��-<�=VS���33��3*�T�+S����ʊiv�-�R �S�j��L�b����]y12�����	������'��vf����)۹�T�NKD�����ٲ��)��N�n8GG�d�Yՠ���jt$Z/��e/*W����H ���^�W�ڔI�a*M��}�:�]W4�=��-��,K%���}i�S�)��^5t�6ǽ`u�t�AQY�6��&�h�Mw���[�/�����=��)�C�E��-�/�3�/��ɱQ�����4k���Z?���w �84���E�1%����{e!v�:]�~��M�i��S�M���l��b�r��7��bB8p�C����xI�^ۘ���(Ψg.b��$��Ä}����PN��_�xP�GW/~c,��Z���,:����]�F�d�x�G�(��ӂ�Nk�}�0�&�n�m�ˣ�ޣy������p�H");
		}
		try {
			TSocket sock = new TSocket("127.0.0.1", port);
			TTransport transport = new TFramedTransport(sock);
			TProtocol protocol = new TBinaryProtocol(transport);
			BcryptService.Client client = new BcryptService.Client(protocol);
			transport.open();
			gate.await();
			List<String> hash = new ArrayList<>();
			for (int i = 0; i < requests; ++i) {
				hash = client.hashPassword(password, (short)10);
			}
			// hash.add(2,"dwqdqwd");
			// System.out.println("Positive check: " + client.checkPassword(password, hash));

			transport.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}