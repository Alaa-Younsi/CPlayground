/* cplayground.c
   Single-file C platform (signup/login with SHA-256 hashes, games, tutorials,
   calculator, profile, persistent users in data/users.db).
   Compile: gcc -std=c11 -O2 -Wall -lm -o cplayground.exe cplayground.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <sys/stat.h>
#include <math.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#define MKDIR(p) mkdir(p, 0755)
#endif

#define DATA_DIR "data"
#define USERS_DB DATA_DIR "/users.db"
#define MAX_USER 64
#define HASH_HEX 65

/* ---------- Utilities ---------- */
void ensure_data_dir(void){
    struct stat st;
    if (stat(DATA_DIR, &st) != 0) {
        MKDIR(DATA_DIR);
    }
}

void read_line(const char *prompt, char *buf, size_t n){
    if(prompt) printf("%s", prompt);
    if(!fgets(buf, (int)n, stdin)){ buf[0]='\0'; return; }
    size_t L = strlen(buf);
    if(L>0 && buf[L-1]=='\n') buf[L-1]='\0';
}

void now_iso(char *out, size_t n){
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(out, n, "%Y-%m-%dT%H:%M:%S", tm);
}

/* ---------- SHA-256 (compact) ---------- */
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]){
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for (i=0,j=0; i < 16; ++i, j+=4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for(i=0;i<64;i++){
        t1 = h + EP1(e) + CH(e,f,g) + k256[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d + t1; d=c; c=b; b=a; a=t1 + t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

void sha256_init(SHA256_CTX *ctx){
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85; ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c; ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len){
    for(size_t i=0;i<len;i++){
        ctx->data[ctx->datalen++] = data[i];
        if(ctx->datalen==64){
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]){
    unsigned i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while(i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while(i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i=0;i<4;i++){
        hash[i]      = (ctx->state[0] >> (24 - i*8)) & 0xff;
        hash[i+4]    = (ctx->state[1] >> (24 - i*8)) & 0xff;
        hash[i+8]    = (ctx->state[2] >> (24 - i*8)) & 0xff;
        hash[i+12]   = (ctx->state[3] >> (24 - i*8)) & 0xff;
        hash[i+16]   = (ctx->state[4] >> (24 - i*8)) & 0xff;
        hash[i+20]   = (ctx->state[5] >> (24 - i*8)) & 0xff;
        hash[i+24]   = (ctx->state[6] >> (24 - i*8)) & 0xff;
        hash[i+28]   = (ctx->state[7] >> (24 - i*8)) & 0xff;
    }
}

void sha256_hex(const char *input, char out_hex[HASH_HEX]){
    SHA256_CTX ctx;
    uint8_t hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)input, strlen(input));
    sha256_final(&ctx, hash);
    for(int i=0;i<32;i++) sprintf(out_hex + i*2, "%02x", hash[i]);
    out_hex[64]=0;
}

/* ---------- User DB ---------- */
typedef struct {
    char username[MAX_USER];
    char hash[HASH_HEX];
    int games_played;
    int games_won;
    int quizzes;
    char last_login[32];
} User;

int load_users(User **arr_out){
    ensure_data_dir();
    FILE *f = fopen(USERS_DB, "r");
    if(!f){ *arr_out = NULL; return 0; }
    User *arr = NULL; int cap=0, n=0;
    char line[512];
    while(fgets(line, sizeof line, f)){
        char user[MAX_USER], hash[HASH_HEX], last_login[32];
        int gp=0, gw=0, q=0;
        int items = sscanf(line, "%63s %64s %d %d %d %31s", user, hash, &gp, &gw, &q, last_login);
        if(items < 2) continue;
        User u;
        memset(&u,0,sizeof u);
        strncpy(u.username, user, sizeof u.username-1);
        strncpy(u.hash, hash, sizeof u.hash-1);
        u.games_played = (items>=3)?gp:0;
        u.games_won = (items>=4)?gw:0;
        u.quizzes = (items>=5)?q:0;
        if(items>=6) strncpy(u.last_login, last_login, sizeof u.last_login-1);
        else u.last_login[0]='\0';
        if(n+1 > cap){ cap = cap?cap*2:8; arr = realloc(arr, cap * sizeof(User)); }
        arr[n++] = u;
    }
    fclose(f);
    *arr_out = arr;
    return n;
}

int save_users(User *arr, int n){
    ensure_data_dir();
    FILE *f = fopen(USERS_DB ".tmp", "w");
    if(!f) return 0;
    for(int i=0;i<n;i++){
        fprintf(f, "%s %s %d %d %d %s\n",
                arr[i].username,
                arr[i].hash,
                arr[i].games_played,
                arr[i].games_won,
                arr[i].quizzes,
                arr[i].last_login[0]?arr[i].last_login:"-");
    }
    fclose(f);
    remove(USERS_DB);
    rename(USERS_DB ".tmp", USERS_DB);
    return 1;
}

int find_user_index(User *arr, int n, const char *username){
    if(!arr) return -1;
    for(int i=0;i<n;i++) if(strcmp(arr[i].username, username)==0) return i;
    return -1;
}

/* ---------- Auth flows ---------- */

void show_all_users(){
    User *arr; int n = load_users(&arr);
    if(n==0){ printf("No users registered.\n"); if(arr) free(arr); return; }
    printf("\n--- Registered Users ---\n");
    for(int i=0;i<n;i++){
        printf("%s | hash=%s | games=%d won=%d quizzes=%d last=%s\n",
               arr[i].username,
               arr[i].hash,
               arr[i].games_played,
               arr[i].games_won,
               arr[i].quizzes,
               arr[i].last_login[0]?arr[i].last_login:"-");
    }
    free(arr);
}

int signup_flow(){
    char username[64], password[128], hash[HASH_HEX];
    read_line("Choose a username: ", username, sizeof username);
    if(strlen(username)==0){ printf("Username cannot be empty.\n"); return 0; }
    read_line("Choose a password: ", password, sizeof password);
    if(strlen(password)==0){ printf("Password cannot be empty.\n"); return 0; }
    sha256_hex(password, hash);
    User *arr; int n = load_users(&arr);
    int idx = find_user_index(arr, n, username);
    if(idx!=-1){ printf("User already exists.\n"); if(arr) free(arr); return 0; }
    User u; memset(&u,0,sizeof u);
    strncpy(u.username, username, sizeof u.username-1);
    strncpy(u.hash, hash, sizeof u.hash-1);
    u.games_played = 0; u.games_won = 0; u.quizzes = 0; u.last_login[0]='-';
    User *newarr = realloc(arr, (n+1)*sizeof(User));
    if(!newarr){ printf("Memory error.\n"); if(arr) free(arr); return 0; }
    newarr[n] = u; n++;
    if(!save_users(newarr, n)){ printf("Error saving user.\n"); free(newarr); return 0; }
    free(newarr);
    printf("Signup successful! You can now log in.\n");
    return 1;
}

int login_flow(char *out_username){
    char username[64], password[128], hash[HASH_HEX];
    read_line("Enter username: ", username, sizeof username);
    read_line("Enter password: ", password, sizeof password);
    sha256_hex(password, hash);
    User *arr; int n = load_users(&arr);
    if(n==0){ printf("No users. Please sign up first.\n"); if(arr) free(arr); return 0; }
    int idx = find_user_index(arr, n, username);
    if(idx==-1){ printf("User not found.\n"); free(arr); return 0; }
    if(strcmp(arr[idx].hash, hash)!=0){ printf("Authentication failed.\n"); free(arr); return 0; }
    now_iso(arr[idx].last_login, sizeof arr[idx].last_login);
    save_users(arr, n);
    free(arr);
    if(out_username) strncpy(out_username, username, MAX_USER-1);
    printf("Login successful. Welcome, %s!\n", username);
    return 1;
}

/* ---------- Profile & Stats ---------- */
void show_profile(const char *username){
    User *arr; int n = load_users(&arr);
    if(n==0){ printf("No profile found.\n"); if(arr) free(arr); return; }
    int idx = find_user_index(arr, n, username);
    if(idx==-1){ printf("Profile not found.\n"); free(arr); return; }
    printf("\n--- Profile: %s ---\n", username);
    printf("Games played: %d\nGames won: %d\nQuizzes completed: %d\nLast login: %s\n",
           arr[idx].games_played, arr[idx].games_won, arr[idx].quizzes, arr[idx].last_login[0]?arr[idx].last_login:"-");
    free(arr);
}

void increment_games_played(const char *username, int won){
    User *arr; int n = load_users(&arr);
    if(n==0){ if(arr) free(arr); return; }
    int idx = find_user_index(arr, n, username);
    if(idx!=-1){
        arr[idx].games_played++;
        if(won) arr[idx].games_won++;
        save_users(arr, n);
    }
    free(arr);
}
void increment_quiz(const char *username){
    User *arr; int n = load_users(&arr);
    if(n==0){ if(arr) free(arr); return; }
    int idx = find_user_index(arr, n, username);
    if(idx!=-1){ arr[idx].quizzes++; save_users(arr, n); }
    free(arr);
}

/* ---------- Games ---------- */
void game_number_guess(const char *username){
    srand((unsigned)time(NULL));
    int target = rand()%100 + 1;
    printf("\n-- Number Guess (1..100) --\n");
    int tries=0, guess;
    char buf[64];
    while(1){
        read_line("Your guess (or 'q' to quit): ", buf, sizeof buf);
        if(buf[0]=='q'){ printf("Quit. The number was %d.\n", target); break; }
        if(sscanf(buf, "%d", &guess)!=1){ printf("Invalid.\n"); continue; }
        tries++;
        if(guess<target) printf("Higher.\n");
        else if(guess>target) printf("Lower.\n");
        else { printf("Correct in %d tries!\n", tries); increment_games_played(username, 1); break; }
    }
}

/* Tic-tac-toe (small AI) */
char ttt_board[9];
int ttt_lines[8][3] = {{0,1,2},{3,4,5},{6,7,8},{0,3,6},{1,4,7},{2,5,8},{0,4,8},{2,4,6}};
void ttt_draw(void){
    printf("\n");
    for(int r=0;r<3;r++){
        for(int c=0;c<3;c++){
            int i=3*r+c; char ch = ttt_board[i]?ttt_board[i]:'0'+i;
            printf(" %c ", ch);
            if(c<2) printf("|");
        }
        printf("\n");
        if(r<2) printf("---+---+---\n");
    }
}
int ttt_winner(void){
    for(int k=0;k<8;k++){
        int a=ttt_lines[k][0], b=ttt_lines[k][1], c=ttt_lines[k][2];
        if(ttt_board[a] && ttt_board[a]==ttt_board[b] && ttt_board[b]==ttt_board[c]){
            return ttt_board[a]=='X'? -1 : 1;
        }
    }
    for(int i=0;i<9;i++) if(!ttt_board[i]) return 2;
    return 0;
}
int ttt_ai_move(void){
    for(int p=0;p<9;p++) if(!ttt_board[p]){
        ttt_board[p]='O';
        if(ttt_winner()==1){ ttt_board[p]=0; return p; }
        ttt_board[p]=0;
    }
    for(int p=0;p<9;p++) if(!ttt_board[p]){
        ttt_board[p]='X';
        if(ttt_winner()==-1){ ttt_board[p]=0; return p; }
        ttt_board[p]=0;
    }
    for(int p=0;p<9;p++) if(!ttt_board[p]) return p;
    return -1;
}
void game_tictactoe(const char *username){
    memset(ttt_board,0,sizeof ttt_board);
    printf("\n-- Tic-Tac-Toe: You = X, AI = O --\n");
    int turn = -1;
    char buf[32];
    while(1){
        ttt_draw();
        int w = ttt_winner();
        if(w!=2){
            if(w==1){ printf("AI wins.\n"); increment_games_played(username, 0); return; }
            else if(w==-1){ printf("You win!\n"); increment_games_played(username, 1); return; }
            else { printf("Draw.\n"); increment_games_played(username, 0); return; }
        }
        if(turn==-1){
            read_line("Your move (0-8): ", buf, sizeof buf);
            int m; if(sscanf(buf, "%d", &m)!=1 || m<0 || m>8 || ttt_board[m]){ printf("Invalid move.\n"); continue; }
            ttt_board[m]='X'; turn=1;
        } else {
            int m = ttt_ai_move();
            if(m>=0) ttt_board[m]='O';
            turn=-1;
        }
    }
}

void games_menu(const char *username){
    while(1){
        printf("\n=== Games ===\n1) Number Guess\n2) Tic-Tac-Toe\n0) Back\nChoose: ");
        char buf[16]; read_line("", buf, sizeof buf);
        if(strcmp(buf,"0")==0) return;
        else if(strcmp(buf,"1")==0) game_number_guess(username);
        else if(strcmp(buf,"2")==0) game_tictactoe(username);
        else printf("Invalid.\n");
    }
}

/* ---------- Tutorials & Quiz ---------- */
void show_tutorial_topic(const char *topic){
    if(strcmp(topic,"basics")==0){
        printf("\n-- Basics --\nVariables, types, printf/scanf, functions.\n");
    } else if(strcmp(topic,"pointers")==0){
        printf("\n-- Pointers --\nPointers, & (address), * (dereference), malloc/free.\n");
    } else if(strcmp(topic,"ds")==0){
        printf("\n-- Data Structures --\nArrays, linked lists, stacks, queues, trees, graphs basics.\n");
    }
}

int run_quiz_simple(const char *username){
    const char *qs[5] = {
        "Which function prints to stdout? (printf/print)",
        "Operator to get variable address? (&/*)",
        "Which header for malloc? (stdlib.h/stdio.h)",
        "Loop that checks condition at end? (do-while/while)",
        "What is array indexing base? (0/1)"
    };
    const char *ans[5] = {"printf","&","stdlib.h","do-while","0"};
    int score=0; char buf[128];
    for(int i=0;i<5;i++){
        printf("\nQ%d) %s\n> ", i+1, qs[i]);
        read_line(NULL, buf, sizeof buf);
        if(strlen(buf)==0){ printf("No answer. Correct: %s\n", ans[i]); continue; }
        for(char *p=buf; *p; ++p) if(*p>='A' && *p<='Z') *p += 'a'-'A';
        if(strcmp(buf, ans[i])==0){ printf("Correct.\n"); score++; }
        else printf("Wrong. Answer: %s\n", ans[i]);
    }
    printf("You scored %d/5\n", score);
    if(score>0) increment_quiz(username);
    return score;
}

void learn_menu(const char *username){
    while(1){
        printf("\n=== Learn C ===\n1) Basics\n2) Pointers\n3) Data Structures\n4) Short Quiz\n0) Back\nChoose: ");
        char buf[16]; read_line("", buf, sizeof buf);
        if(strcmp(buf,"0")==0) return;
        if(strcmp(buf,"1")==0) show_tutorial_topic("basics");
        else if(strcmp(buf,"2")==0) show_tutorial_topic("pointers");
        else if(strcmp(buf,"3")==0) show_tutorial_topic("ds");
        else if(strcmp(buf,"4")==0) run_quiz_simple(username);
        else printf("Invalid.\n");
    }
}

/* ---------- Algorithms demo ---------- */
static int cmp_int(const void *a, const void *b){
    int ia = *(const int*)a;
    int ib = *(const int*)b;
    return (ia > ib) - (ia < ib);
}

void demo_sorting(void){
    char buf[32]; int n=0;
    read_line("Enter array size (5..20): ", buf, sizeof buf);
    if(sscanf(buf, "%d", &n)!=1 || n<5 || n>20){ printf("Invalid size.\n"); return; }
    int *a = malloc(n*sizeof(int));
    srand((unsigned)time(NULL));
    for(int i=0;i<n;i++) a[i]=rand()%100;
    printf("Original: ");
    for(int i=0;i<n;i++) printf("%d ", a[i]); printf("\n");
    read_line("Choose: 1) Bubble 2) Insertion 3) Quick (qsort)\nChoice: ", buf, sizeof buf);
    if(strcmp(buf,"1")==0){
        for(int i=0;i<n-1;i++) for(int j=0;j<n-1-i;j++) if(a[j]>a[j+1]){ int t=a[j]; a[j]=a[j+1]; a[j+1]=t; }
    } else if(strcmp(buf,"2")==0){
        for(int i=1;i<n;i++){ int key=a[i], j=i-1; while(j>=0 && a[j]>key){ a[j+1]=a[j]; j--; } a[j+1]=key; }
    } else {
        qsort(a, n, sizeof(int), cmp_int);
    }
    printf("Sorted: ");
    for(int i=0;i<n;i++) printf("%d ", a[i]); printf("\n");
    free(a);
}

void demo_binary_search(void){
    int n=10; int *a = malloc(n*sizeof(int));
    for(int i=0;i<n;i++) a[i]=i*2;
    printf("Array: ");
    for(int i=0;i<n;i++) printf("%d ", a[i]); printf("\n");
    char buf[32]; read_line("Search for: ", buf, sizeof buf);
    int key = atoi(buf);
    int l=0, r=n-1, found=-1, steps=0;
    while(l<=r){
        steps++;
        int m=(l+r)/2;
        if(a[m]==key){ found=m; break; }
        else if(a[m]<key) l=m+1; else r=m-1;
    }
    if(found>=0) printf("Found at index %d in %d steps.\n", found, steps);
    else printf("Not found after %d steps.\n", steps);
    free(a);
}

/* ---------- Calculator ---------- */
void calc_basic(void){
    char buf[128];
    double a,b; char op;
    read_line("Enter expression (e.g. 2 + 3): ", buf, sizeof buf);
    if(sscanf(buf, "%lf %c %lf", &a, &op, &b)!=3){ printf("Invalid.\n"); return; }
    if(op=='+') printf("= %.10g\n", a+b);
    else if(op=='-') printf("= %.10g\n", a-b);
    else if(op=='*') printf("= %.10g\n", a*b);
    else if(op=='/') { if(b==0) printf("Divide by zero.\n"); else printf("= %.10g\n", a/b); }
    else printf("Op not supported.\n");
}

void calc_quadratic(void){
    char buf[128]; double a,b,c;
    read_line("Enter a b c (ax^2 + bx + c): ", buf, sizeof buf);
    if(sscanf(buf, "%lf %lf %lf", &a,&b,&c)!=3){ printf("Invalid.\n"); return; }
    double D = b*b - 4*a*c;
    if(D < 0){ printf("No real roots.\n"); return; }
    double r1 = (-b + sqrt(D))/(2*a);
    double r2 = (-b - sqrt(D))/(2*a);
    printf("Roots: %g , %g\n", r1, r2);
}

void calc_matrix(void){
    printf("Enter A (a11 a12 a21 a22): ");
    double a11,a12,a21,a22;
    if(scanf("%lf %lf %lf %lf", &a11,&a12,&a21,&a22)!=4){ printf("Invalid.\n"); while(getchar()!='\n'); return; }
    printf("Enter B (b11 b12 b21 b22): ");
    double b11,b12,b21,b22;
    if(scanf("%lf %lf %lf %lf", &b11,&b12,&b21,&b22)!=4){ printf("Invalid.\n"); while(getchar()!='\n'); return; }
    while(getchar()!='\n');
    printf("A+B =\n%g %g\n%g %g\n", a11+b11,a12+b12,a21+b21,a22+b22);
    double c11=a11*b11 + a12*b21, c12=a11*b12 + a12*b22, c21=a21*b11 + a22*b21, c22=a21*b12 + a22*b22;
    printf("A*B =\n%g %g\n%g %g\n", c11,c12,c21,c22);
}

void calculator_menu(void){
    while(1){
        printf("\n=== Advanced Calculator ===\n1) Basic\n2) Quadratic solver\n3) 2x2 Matrices\n0) Back\nChoose: ");
        char buf[16]; read_line("", buf, sizeof buf);
        if(strcmp(buf,"0")==0) return;
        if(strcmp(buf,"1")==0) calc_basic();
        else if(strcmp(buf,"2")==0) calc_quadratic();
        else if(strcmp(buf,"3")==0) calc_matrix();
        else printf("Invalid.\n");
    }
}

/* ---------- Platform Home ---------- */
void platform_home(const char *username){
    while(1){
        printf("\n=== Welcome, %s ===\n1) Games\n2) Learn C\n3) Algorithms demo\n4) Advanced Calculator\n5) Profile\n6) Show users (admin)\n0) Logout\nChoose: ", username);
        char opt[16]; read_line("", opt, sizeof opt);
        if(strcmp(opt,"0")==0){ printf("Logging out...\n"); break; }
        else if(strcmp(opt,"1")==0) games_menu(username);
        else if(strcmp(opt,"2")==0) learn_menu(username);
        else if(strcmp(opt,"3")==0){
            printf("1) Sorting 2) Binary Search\n");
            char s[8]; read_line("Choose: ", s, sizeof s);
            if(strcmp(s,"1")==0) demo_sorting();
            else if(strcmp(s,"2")==0) demo_binary_search();
        }
        else if(strcmp(opt,"4")==0) calculator_menu();
        else if(strcmp(opt,"5")==0) show_profile(username);
        else if(strcmp(opt,"6")==0) show_all_users();
        else printf("Invalid option.\n");
    }
}

/* ---------- Startup loop ---------- */
void startup_loop(void){
    ensure_data_dir();
    while(1){
        printf("\n=== CPlayground Startup ===\n1) Sign Up\n2) Log In\n3) Show Users (admin)\n0) Exit\nChoose: ");
        char buf[16]; read_line("", buf, sizeof buf);
        if(strcmp(buf,"0")==0){ printf("Bye.\n"); exit(0); }
        else if(strcmp(buf,"1")==0){
            if(signup_flow()){
                char ans[8]; read_line("Login now? (y/n): ", ans, sizeof ans);
                if(ans[0]=='y' || ans[0]=='Y'){ char user[MAX_USER]; if(login_flow(user)) platform_home(user); }
            }
        }
        else if(strcmp(buf,"2")==0){
            char user[MAX_USER] = {0};
            if(login_flow(user)) platform_home(user);
        }
        else if(strcmp(buf,"3")==0) show_all_users();
        else printf("Invalid.\n");
    }
}

/* ---------- main ---------- */
int main(void){
    printf("CPlayground — C platform demo\n");
    startup_loop();
    return 0;
}
