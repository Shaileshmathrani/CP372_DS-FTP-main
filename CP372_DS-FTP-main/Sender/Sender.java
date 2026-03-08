import java.net.*;
import java.io.*;
import java.util.*;

/**
 * DS-FTP Sender Implementation
 * 
 * Implements both Stop-and-Wait and Go-Back-N protocol variants
 * 
 * Command line: 
 *   Stop-and-Wait: java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> <input_file> <timeout_ms>
 *   Go-Back-N:    java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> <input_file> <timeout_ms> <window_size>
 */
public class Sender {
    
    // Socket for receiving ACKs
    private DatagramSocket ackSocket;
    
    // Receiver's address and port for data packets
    private InetAddress receiverAddress;
    private int receiverDataPort;
    
    // Sender's ACK listening port
    private int senderAckPort;
    
    // Input file
    private String inputFileName;
    private FileInputStream fileInputStream;
    
    // Protocol parameters
    private int timeoutMs;
    private Integer windowSize;
    
    // Protocol state
    private int base = 0;
    private int nextSeqNum = 0;
    
    // Timeout management
    private long lastPacketSentTime;
    private int consecutiveTimeouts = 0;
    private int lastBase = -1;
    private int consecutiveTimeoutsForSamePacket = 0;
    private static final int MAX_CONSECUTIVE_TIMEOUTS = 3;
    
    // Packet storage
    private List<DSPacket> allDataPackets = new ArrayList<>();
    
    // Statistics
    private int packetsSent = 0;
    private int packetsRetransmitted = 0;
    private int timeoutsOccurred = 0;
    
    // File information
    private long fileSize;
    private int totalPackets;
    private int lastDataSeqNum = 0;
    
    // Timing
    private long startTime;
    private long endTime;
    
    // Logging
    private PrintWriter logger;
    private boolean debugMode = true; // Set to true for video to show output
    
    public Sender(String rcvIp, int rcvDataPort, int senderAckPort, 
                  String inputFile, int timeoutMs, Integer windowSize) throws Exception {
        
        this.receiverAddress = InetAddress.getByName(rcvIp);
        this.receiverDataPort = rcvDataPort;
        this.senderAckPort = senderAckPort;
        this.inputFileName = inputFile;
        this.timeoutMs = timeoutMs;
        this.windowSize = windowSize;
        
        // Create socket for receiving ACKs
        ackSocket = new DatagramSocket(senderAckPort);
        ackSocket.setReuseAddress(true);
        
        // Open input file
        File file = new File(inputFileName);
        if (!file.exists()) {
            throw new FileNotFoundException("Input file not found: " + inputFileName);
        }
        fileSize = file.length();
        fileInputStream = new FileInputStream(file);
        
        // Calculate total packets
        totalPackets = (int) Math.ceil((double) fileSize / DSPacket.MAX_PAYLOAD_SIZE);
        
        // Setup logging
        logger = new PrintWriter(new FileWriter("sender_log.txt"), true);
        log("Sender started");
        log("Sending to " + rcvIp + ":" + rcvDataPort);
        log("Listening for ACKs on port " + senderAckPort);
        log("Timeout: " + timeoutMs + "ms");
        log("Window size: " + (windowSize == null ? "Stop-and-Wait" : windowSize));
        log("File: " + inputFile + " (" + fileSize + " bytes, " + totalPackets + " packets)");
    }
    
    /**
     * Main sender logic
     */
    public void run() throws Exception {
        startTime = System.currentTimeMillis();
        
        try {
            // Phase 1: Handshake
            if (!performHandshake()) {
                log("Handshake failed. Exiting.");
                return;
            }
            
            // Phase 2: Data Transfer
            if (fileSize == 0) {
                sendEOT();
                waitForEOTAck();
                return;
            }
            
            // Read all file data into packets
            readAllPackets();
            
            if (windowSize == null) {
                runStopAndWait();
            } else {
                runGoBackN();
            }
            
            // Phase 3: Wait for EOT ACK
            waitForEOTAck();
            
        } catch (Exception e) {
            log("Error during transfer: " + e.getMessage());
            e.printStackTrace();
        } finally {
            cleanup();
        }
    }
    
    /**
     * Read all file data into packets
     */
    private void readAllPackets() throws Exception {
        byte[] buffer = new byte[DSPacket.MAX_PAYLOAD_SIZE];
        int bytesRead;
        int seq = 1;
        
        while ((bytesRead = fileInputStream.read(buffer)) != -1) {
            if (bytesRead > 0) {
                byte[] payload = Arrays.copyOf(buffer, bytesRead);
                allDataPackets.add(new DSPacket(DSPacket.TYPE_DATA, seq, payload));
                seq = (seq + 1) % 128;
            }
        }
        
        lastDataSeqNum = (seq - 1 + 128) % 128;
        log("File read complete: " + allDataPackets.size() + " packets");
    }
    
    /**
     * Perform handshake
     */
    private boolean performHandshake() throws Exception {
        log("Starting handshake...");
        
        DSPacket sotPacket = new DSPacket(DSPacket.TYPE_SOT, 0, null);
        
        for (int attempts = 0; attempts < MAX_CONSECUTIVE_TIMEOUTS; attempts++) {
            sendPacket(sotPacket);
            log("Sent SOT, waiting for ACK...");
            
            try {
                ackSocket.setSoTimeout(timeoutMs);
                DSPacket ack = receiveAck();
                if (ack.getType() == DSPacket.TYPE_ACK && ack.getSeqNum() == 0) {
                    log("Handshake successful: Received ACK for SOT");
                    base = 0;
                    nextSeqNum = 1;
                    return true;
                }
            } catch (SocketTimeoutException e) {
                log("Handshake timeout " + (attempts + 1) + "/" + MAX_CONSECUTIVE_TIMEOUTS);
            }
        }
        
        return false;
    }
    
    /**
     * Run Stop-and-Wait protocol
     */
    private void runStopAndWait() throws Exception {
        log("Starting Stop-and-Wait data transfer");
        
        int currentSeq = 1;
        int packetIndex = 0;
        
        while (packetIndex < allDataPackets.size()) {
            DSPacket packet = allDataPackets.get(packetIndex);
            
            boolean ackReceived = false;
            consecutiveTimeouts = 0;
            consecutiveTimeoutsForSamePacket = 0;
            
            while (!ackReceived && consecutiveTimeouts < MAX_CONSECUTIVE_TIMEOUTS) {
                sendPacket(packet);
                log("Stop-and-Wait: Sent DATA packet " + currentSeq);
                packetsSent++;
                
                try {
                    ackSocket.setSoTimeout(timeoutMs);
                    DSPacket ack = receiveAck();
                    
                    if (ack.getType() == DSPacket.TYPE_ACK && ack.getSeqNum() == currentSeq) {
                        log("Stop-and-Wait: Received ACK for packet " + currentSeq);
                        ackReceived = true;
                        consecutiveTimeouts = 0;
                        consecutiveTimeoutsForSamePacket = 0;
                        currentSeq = (currentSeq + 1) % 128;
                        packetIndex++;
                    }
                } catch (SocketTimeoutException e) {
                    consecutiveTimeouts++;
                    consecutiveTimeoutsForSamePacket++;
                    timeoutsOccurred++;
                    log("Stop-and-Wait: Timeout " + consecutiveTimeouts + 
                        "/" + MAX_CONSECUTIVE_TIMEOUTS + " for packet " + currentSeq);
                    
                    if (consecutiveTimeoutsForSamePacket >= MAX_CONSECUTIVE_TIMEOUTS) {
                        throw new Exception("Critical failure - too many timeouts for packet " + currentSeq);
                    }
                }
            }
        }
        
        lastDataSeqNum = (currentSeq - 1 + 128) % 128;
    }
    
    /**
     * Run Go-Back-N protocol
     */
    private void runGoBackN() throws Exception {
        log("Starting Go-Back-N data transfer with window size " + windowSize);
        
        base = 1;
        nextSeqNum = 1;
        lastPacketSentTime = System.currentTimeMillis();
        
        while (base <= totalPackets) {
            // Send packets in window
            while (nextSeqNum < base + windowSize && nextSeqNum <= totalPackets) {
                DSPacket packet = allDataPackets.get(nextSeqNum - 1);
                
                // Apply permutation for groups of 4
                if (nextSeqNum % 4 == 1 && nextSeqNum + 3 <= totalPackets) {
                    sendPermutedGroup(nextSeqNum - 1);
                    nextSeqNum += 4;
                } else {
                    sendPacket(packet);
                    log("GBN: Sent packet " + packet.getSeqNum() + " (base=" + base + ")");
                    nextSeqNum++;
                }
                
                packetsSent++;
                lastPacketSentTime = System.currentTimeMillis();
            }
            
            // Wait for ACKs
            boolean progress = false;
            long timeoutTime = System.currentTimeMillis() + timeoutMs;
            
            while (System.currentTimeMillis() < timeoutTime) {
                try {
                    ackSocket.setSoTimeout(10);
                    DSPacket ack = receiveAck();
                    
                    if (ack.getType() == DSPacket.TYPE_ACK) {
                        int ackNum = ack.getSeqNum();
                        log("GBN: Received ACK " + ackNum);
                        
                        if (ackNum >= base) {
                            int oldBase = base;
                            base = ackNum + 1;
                            
                            if (base > oldBase) {
                                log("GBN: Base moved from " + oldBase + " to " + base);
                                progress = true;
                                consecutiveTimeouts = 0;
                                consecutiveTimeoutsForSamePacket = 0;
                                lastBase = -1;
                                lastPacketSentTime = System.currentTimeMillis();
                            }
                            
                            if (base > totalPackets) {
                                break;
                            }
                        }
                    }
                } catch (SocketTimeoutException e) {
                    // No ACK, continue waiting
                }
            }
            
            // Handle timeout if no progress
            if (!progress && base <= totalPackets) {
                handleTimeout();
                nextSeqNum = base;
            }
        }
        
        log("GBN data transfer complete");
    }
    
    /**
     * Send a permuted group of 4 packets
     */
    private void sendPermutedGroup(int startIndex) throws Exception {
        List<DSPacket> group = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            group.add(allDataPackets.get(startIndex + i));
        }
        
        List<DSPacket> permuted = ChaosEngine.permutePackets(group);
        
        for (DSPacket p : permuted) {
            sendPacket(p);
            log("GBN: Sent packet " + p.getSeqNum() + " (permuted)");
        }
    }
    
    /**
     * Handle timeout in GBN mode
     */
    private void handleTimeout() throws Exception {
        timeoutsOccurred++;
        consecutiveTimeouts++;
        
        log("GBN: Timeout occurred (timeout #" + consecutiveTimeouts + ", base=" + base + ")");
        
        if (base == lastBase) {
            consecutiveTimeoutsForSamePacket++;
            if (consecutiveTimeoutsForSamePacket >= MAX_CONSECUTIVE_TIMEOUTS) {
                throw new Exception("Critical failure - too many timeouts for base=" + base);
            }
        } else {
            consecutiveTimeoutsForSamePacket = 1;
            lastBase = base;
        }
        
        int endSeq = Math.min(base + windowSize - 1, totalPackets);
        log("GBN: Retransmitting window from base " + base + " to " + endSeq);
        
        for (int i = base; i <= endSeq; i++) {
            DSPacket packet = allDataPackets.get(i - 1);
            sendPacket(packet);
            log("GBN: Retransmitted packet " + packet.getSeqNum());
            packetsRetransmitted++;
            packetsSent++;
        }
        
        lastPacketSentTime = System.currentTimeMillis();
    }
    
    /**
     * Send EOT packet
     */
    private void sendEOT() throws Exception {
        int eotSeq = (fileSize == 0) ? 1 : (lastDataSeqNum + 1) % 128;
        DSPacket eotPacket = new DSPacket(DSPacket.TYPE_EOT, eotSeq, null);
        sendPacket(eotPacket);
        log("Sent EOT with seq " + eotSeq);
        packetsSent++;
    }
    
    /**
     * Wait for EOT acknowledgment
     */
    private void waitForEOTAck() throws Exception {
        for (int attempts = 0; attempts < MAX_CONSECUTIVE_TIMEOUTS; attempts++) {
            try {
                ackSocket.setSoTimeout(timeoutMs);
                DSPacket ack = receiveAck();
                if (ack.getType() == DSPacket.TYPE_ACK) {
                    log("Received EOT ACK for seq " + ack.getSeqNum());
                    endTime = System.currentTimeMillis();
                    double totalTime = (endTime - startTime) / 1000.0;
                    System.out.printf("Total Transmission Time: %.3f seconds%n", totalTime);
                    return;
                }
            } catch (SocketTimeoutException e) {
                log("EOT ACK timeout " + (attempts + 1) + "/" + MAX_CONSECUTIVE_TIMEOUTS);
                if (attempts < MAX_CONSECUTIVE_TIMEOUTS - 1) {
                    sendEOT();
                }
            }
        }
    }
    
    /**
     * Send a packet (simplified version)
     */
    private void sendPacket(DSPacket packet) throws Exception {
        byte[] data = packet.toBytes();
        DatagramPacket dp = new DatagramPacket(data, data.length, receiverAddress, receiverDataPort);
        ackSocket.send(dp);
    }
    
    /**
     * Receive an ACK packet
     */
    private DSPacket receiveAck() throws Exception {
        byte[] buffer = new byte[DSPacket.MAX_PACKET_SIZE];
        DatagramPacket dp = new DatagramPacket(buffer, buffer.length);
        ackSocket.receive(dp);
        return new DSPacket(dp.getData());
    }
    
    /**
     * Clean up resources
     */
    private void cleanup() throws Exception {
        if (fileInputStream != null) fileInputStream.close();
        if (ackSocket != null && !ackSocket.isClosed()) ackSocket.close();
        if (logger != null) {
            log("\n=== Transfer Statistics ===");
            log("Total packets sent: " + packetsSent);
            log("Packets retransmitted: " + packetsRetransmitted);
            log("Timeouts occurred: " + timeoutsOccurred);
            logger.close();
        }
    }
    
    /**
     * Logging utility
     */
    private void log(String message) {
        if (debugMode) {
            String timestamp = new java.text.SimpleDateFormat("HH:mm:ss.SSS").format(new Date());
            String logMessage = "[" + timestamp + "] " + message;
            System.out.println(logMessage);
            if (logger != null) {
                logger.println(logMessage);
            }
        }
    }
    
    public static void main(String[] args) {
        if (args.length < 5 || args.length > 6) {
            System.err.println("Usage: java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> " +
                             "<input_file> <timeout_ms> [window_size]");
            System.exit(1);
        }
        
        try {
            String rcvIp = args[0];
            int rcvDataPort = Integer.parseInt(args[1]);
            int senderAckPort = Integer.parseInt(args[2]);
            String inputFile = args[3];
            int timeoutMs = Integer.parseInt(args[4]);
            Integer windowSize = (args.length == 6) ? Integer.parseInt(args[5]) : null;
            
            if (windowSize != null && (windowSize <= 0 || windowSize > 128 || windowSize % 4 != 0)) {
                System.err.println("Window size must be a multiple of 4 between 1 and 128");
                System.exit(1);
            }
            
            Sender sender = new Sender(rcvIp, rcvDataPort, senderAckPort, 
                                      inputFile, timeoutMs, windowSize);
            sender.run();
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}
