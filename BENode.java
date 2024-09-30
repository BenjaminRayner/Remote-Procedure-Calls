import java.net.InetAddress;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import org.apache.thrift.TProcessorFactory;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.server.TThreadPoolServer;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TServerSocket;

public class BENode {
	static Logger log;

	public static void main(String [] args) throws Exception {
		if (args.length != 3) {
			System.err.println("Usage: java BENode FE_host FE_port BE_port");
			System.exit(-1);
		}

		// initialize log4j
		BasicConfigurator.configure();
		log = Logger.getLogger(BENode.class.getName());

		String hostFE = args[0];
		int portFE = Integer.parseInt(args[1]);
		int portBE = Integer.parseInt(args[2]);
		log.info("Launching BE node on port " + portBE + " at host " + getHostName());

		// connect with FE server
		new Thread(new contactFE(hostFE, portFE, getHostName(), portBE)).start();

		// launch Thrift server (multithreaded)
		BcryptServiceBE.Processor processor = new BcryptServiceBE.Processor<BcryptServiceBE.Iface>(new BcryptServiceBEHandler());
		TServerSocket socket = new TServerSocket(portBE);
		TThreadPoolServer.Args sargs = new TThreadPoolServer.Args(socket);
		sargs.protocolFactory(new TBinaryProtocol.Factory());
		sargs.transportFactory(new TFramedTransport.Factory());
		sargs.processorFactory(new TProcessorFactory(processor));
		TThreadPoolServer server = new TThreadPoolServer(sargs);
		server.serve();
	}

	static String getHostName()
	{
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (Exception e) {
			return "localhost";
		}
	}
}

class contactFE extends Thread
{
	String hostFE;
	int portFE;
	String hostBE;
	int portBE;
	contactFE(String hostFE, int portFE, String hostBE, int portBE) {
		this.hostFE = hostFE;
		this.portFE = portFE;
		this.hostBE = hostBE;
		this.portBE = portBE;
	}

	public void run()
	{
		//Let FE node know BE is up
		while (true) {
			try {
				TSocket sock = new TSocket(hostFE, portFE);
				TTransport transport = new TFramedTransport(sock);
				TProtocol protocol = new TBinaryProtocol(transport);
				BcryptService.Client client = new BcryptService.Client(protocol);
				transport.open();
				client.backendUp(hostBE, portBE);
				transport.close();
				break;
			} catch (Exception e) {
				continue;
			}
		}
	}
}
