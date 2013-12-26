package com.olympe;

import java.io.*;
import java.util.*;

public abstract class Tail extends Thread 
{
	private File file;
	private boolean started = false;
	private boolean suspended = false;
	private long filePointer = 0L;
	
	public long checkInterval = 1000;
	public boolean fromStart = false;
	public boolean failIfNotExist = true;
	
	private Tail() { }

	public Tail( String file )
	{
		this.file = new File(file);
	}
	
	protected abstract void data(String line);
	protected abstract void error(Exception e);

	public void suspendTail()
	{
		if( !started )
			throw new IllegalStateException("Cannot suspend if not started");

		suspended = true;
	}
	
	public void resumeTail()
	{
		if( !suspended )
			throw new IllegalStateException("Cannot resume if not suspended");
	}
	
	public void restartTail()
	{
		if( fromStart )
			this.filePointer = 0;
		else
			this.filePointer = this.file.length();
	}
	
	public void stopTail()
	{
		this.started = false;
	}
	
	public void startTail()
	{
		this.started = true;
		this.start();
	}
	
	public void run()
	{
		long length = 0L;
		RandomAccessFile raf = null;
		String line = null;
		
		try
		{
			while( started )
			{
				while( suspended )
					Thread.sleep(checkInterval);
				
				if( !this.file.canRead() )
				{
					if( failIfNotExist )
						throw new IOException("File does not exist or cannot be read");
					if( raf != null ) try { raf.close(); } catch(Exception ioe) { }
					raf = null;
				}
				else
				{
					length = this.file.length();
					
					if( raf == null || length < filePointer )
					{
						if( raf != null ) try { raf.close(); } catch(Exception ioe) { }

						raf = new RandomAccessFile(this.file, "r");
						this.restartTail();
					}

					if( filePointer < length )
					{
						raf.seek(filePointer);
						
						while( (line = raf.readLine()) != null )
							try { data(line); } catch( Exception ex ) { error(ex); }
						
						filePointer = raf.getFilePointer();
					}
				}
				
				Thread.sleep(checkInterval);
			}
		}
		catch(Exception e)
		{
			this.error(e);
		}
		finally
		{
			this.started = false;
			this.suspended = false;
			this.filePointer = 0;
			
			if( raf != null )
				try { raf.close(); } catch(Exception ex) { }
		}
	}
}