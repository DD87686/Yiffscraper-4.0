import asyncio
import time
import tkinter as tk
import webbrowser
import threading
import aiohttp
import aiofiles
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import io
import os
from zipfile import ZipFile
import sys
import logging
import requests
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
class ConsoleRedirector:
    def __init__(self):
        self.buffer = ""
    def write(self, s):
        self.buffer += s
    def flush(self):
        pass
    def get_buffer(self):
        return self.buffer
logging.basicConfig(
    level=logging.INFO,
    filename="scraper.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s"
)
HEADERS = {'User-Agent': 'Yiffscraper v4.0 (by axo!)'}
BASE_URL = "https://e621.net/posts.json?tags={}&limit={}"
async def fetch_post_details(post_id, session, auth, debug=False):
    url = f"https://e621.net/posts/{post_id}.json"
    async with session.get(url, auth=auth, headers=HEADERS) as resp:
        if resp.status == 200:
            json_data = await resp.json()
            post = json_data.get("post", {})
            score = post.get("score", {})
            total_votes = score.get("total", 0)
            fav = post.get("has_favorited", False)
            fav_count = post.get("fav_count", 0)
            return total_votes, fav, fav_count
        else:
            if debug:
                print(f"[DEBUG] Failed to fetch details for post {post_id}. HTTP {resp.status}")
            return 0, False, 0

def upvote_post_api(username, api_key, post_id):
    url = f"https://e621.net/posts/{post_id}/votes.json"
    data = {"score": 1}
    auth = (username, api_key)
    r = requests.post(url, data=data, auth=auth, headers=HEADERS)
    if r.status_code == 200:
        response = r.json()
        new_votes = response.get("post", {}).get("score", {}).get("total", None)
        return new_votes
    else:
        raise Exception(f"Upvote failed with status {r.status_code}: {r.text}")

def favourite_post_api(username, api_key, post_id, create=True):
    auth = (username, api_key)
    if create:
        url = "https://e621.net/favorites.json"
        data = {"post_id": post_id}
        r = requests.post(url, data=data, auth=auth, headers=HEADERS)
        if r.status_code in (200, 201, 422):
            return True
        else:
            raise Exception(f"Favorite creation failed with status {r.status_code}: {r.text}")
    else:
        url = f"https://e621.net/favorites/{post_id}.json"
        r = requests.delete(url, auth=auth, headers=HEADERS)
        if r.status_code == 200:
            return False
        else:
            raise Exception(f"Favorite deletion failed with status {r.status_code}: {r.text}")
async def get_json(url, session, debug=False):
    if debug:
        print(f"[DEBUG] Sending GET request to {url}")
    async with session.get(url, headers=HEADERS) as response:
        if debug:
            print(f"[DEBUG] Received status: {response.status}")
        if response.status == 200:
            return await response.json()
        else:
            if debug:
                print(f"[DEBUG] Failed GET request with status: {response.status}")
            return None

async def download_file(sem, file_url, post_id, session, download_folder, debug=False, job_callback=None, auth=None, cookies=None):
    async with sem:
        try:
            if job_callback:
                job_callback(post_id, f"Saving {post_id} to {download_folder}")
            if debug:
                print(f"[DEBUG] Downloading post {post_id} from {file_url}")
            async with session.get(file_url, headers=HEADERS, auth=auth, cookies=cookies) as response:
                if response.status == 200:
                    ext = file_url.split('.')[-1]
                    fname = f"{post_id}.{ext}"
                    path = os.path.join(download_folder, fname)
                    data = await response.read()
                    async with aiofiles.open(path, 'wb') as f:
                        await f.write(data)
                    if debug:
                        print(f"[DEBUG] Saved {fname}")
                    if job_callback:
                        job_callback(post_id, f"Completed {post_id}")
                else:
                    if debug:
                        print(f"[DEBUG] HTTP {response.status} for post {post_id}")
                    if job_callback:
                        job_callback(post_id, f"Error {response.status}")
        except Exception as e:
            if debug:
                print(f"[DEBUG] Exception {e}")
            if job_callback:
                job_callback(post_id, f"Error: {e}")

async def start_scraper(query_tags, total_images, thread_limit, download_folder, debug=False, job_callback=None, auth=None, cookies=None):
    os.makedirs(download_folder, exist_ok=True)
    sem = asyncio.Semaphore(thread_limit)
    async with aiohttp.ClientSession(auth=auth, cookies=cookies) as session:
        downloaded = 0
        while downloaded < total_images:
            count = total_images - downloaded
            url = BASE_URL.format(query_tags, count)
            if debug:
                print(f"[DEBUG] Request URL: {url}")
            data = await get_json(url, session, debug)
            if not data or 'posts' not in data:
                if debug:
                    print("[DEBUG] No data or missing 'posts'.")
                break
            tasks = []
            for post in data['posts']:
                file_url = post.get('file', {}).get('url') or post.get('sample', {}).get('url')
                if file_url:
                    tasks.append(download_file(sem, file_url, post['id'], session, download_folder, debug, job_callback, auth, cookies))
            if not tasks:
                if debug:
                    print("[DEBUG] No download tasks created.")
                break
            await asyncio.gather(*tasks)
            downloaded += len(tasks)
            if debug:
                print(f"[DEBUG] Downloaded {downloaded}/{total_images} images.")
        if debug:
            print("[DEBUG] Scraping complete.")


def zip_folder(src_folder, dest_zip_file):
    with ZipFile(dest_zip_file, 'w') as zipf:
        for foldername, _, filenames in os.walk(src_folder):
            for filename in filenames:
                filepath = os.path.join(foldername, filename)
                arcname = os.path.relpath(filepath, src_folder)
                zipf.write(filepath, arcname)
class LoginDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Log In")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result = None
        ttk.Label(self, text="Username:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.username_entry = ttk.Entry(self, width=20)
        self.username_entry.grid(row=0, column=1, padx=10, pady=5)
        ttk.Label(self, text="API Key:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.apikey_entry = ttk.Entry(self, width=20, show="*")
        self.apikey_entry.grid(row=1, column=1, padx=10, pady=5)
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=2, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="Log In", command=self.on_login).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side="left", padx=5)
    def on_login(self):
        username = self.username_entry.get().strip()
        apikey = self.apikey_entry.get().strip()
        if not username or not apikey:
            messagebox.showerror("Error", "Both username and API key are required.")
            return
        test_url = "https://e621.net/posts.json?tags=rating:safe&limit=1"
        auth = (username, apikey)
        r = requests.get(test_url, auth=auth, headers=HEADERS)
        if r.status_code == 200:
            self.result = (username, apikey)
            self.destroy()
        else:
            messagebox.showerror("Authentication Failed", f"Server responded with status {r.status_code}.")

class ViewerDownloaderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("YiffScraper v4.0")
        try:
            self.wm_iconbitmap(resource_path("icon.ico"))
        except Exception:
            pass

        self.geometry(f"1035x900+450+100")
        self.configure(bg="#2e2e2e")

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#2e2e2e")
        style.configure("TLabel", background="#2e2e2e", foreground="#e0e0e0", font=("Segoe UI", 10))
        style.configure("TButton", background="#444444", foreground="#e0e0e0", font=("Segoe UI", 10))
        style.configure("TEntry", fieldbackground="#3c3f41", foreground="#e0e0e0", font=("Segoe UI", 10))
        style.map("TButton",
                  background=[("active", "#555555")],
                  foreground=[("active", "#ffffff")])

        self.preview_images = []
        self.stop_preview = False
        self.username = None
        self.api_key = None
        self.console_redirector = ConsoleRedirector()
        self.original_stdout = sys.stdout
        sys.stdout = self.console_redirector
        self.vote_data = {}

        options_frame = ttk.Frame(self)
        options_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        self.login_button = ttk.Button(options_frame, text="Log In", command=self.log_in)
        self.login_button.grid(row=0, column=9, padx=5, pady=5)

        ttk.Label(options_frame, text="Tags:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.tags_entry = ttk.Entry(options_frame, width=47)
        self.tags_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.tags_entry.bind("<KeyRelease>", lambda e: self.compute_query_tags())

        self.computed_tags_listbox = tk.Listbox(options_frame, fg="#e0e0e0", bg="#3c3f41", width=40, font=("Segoe UI", 10))
        self.computed_tags_listbox.grid(row=1, column=1, padx=5, pady=2, sticky="w")

        ttk.Label(options_frame, text="Preview Count:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.preview_count_entry = ttk.Entry(options_frame, width=6)
        self.preview_count_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")
        self.preview_count_entry.insert(0, "0")

        self.debug_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Enable Debug", variable=self.debug_var).grid(row=0, column=10, padx=5, pady=5)
        ttk.Button(options_frame, text="Cheatsheet", command=self.cheatsheet).grid(row=0, column=2, padx=5, pady=5)

        self.PreviewText = tk.StringVar(value="Preview")
        self.preview_button = ttk.Button(options_frame, textvariable=self.PreviewText, command=self.start_preview_thread)
        self.preview_button.grid(row=0, column=3, padx=5, pady=5)

        self.stop_preview_button = ttk.Button(options_frame, text="Stop Preview", command=self.stop_preview_loading)
        self.stop_preview_button.grid(row=0, column=4, padx=5, pady=5)

        ttk.Button(options_frame, text="Download", command=self.open_download_dialog).grid(row=0, column=5, padx=5, pady=5)

        self.preview_frame = ttk.Frame(self)
        self.preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.canvas = tk.Canvas(self.preview_frame, background="#2e2e2e", highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.preview_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text = tk.Text(self, height=4, state="disabled", bg="#3c3f41", fg="#e0e0e0", font=("Segoe UI", 10))
        self.log_text.pack(fill="x", padx=10, pady=5)

        self.job_listbox = tk.Listbox(self, height=4, bg="#3c3f41", fg="#e0e0e0", font=("Segoe UI", 10))
        self.job_listbox.pack(fill="x", padx=10, pady=5)
        self.job_map = {}

        self.console_button = ttk.Button(self, text="Show Console", command=self.show_console_window)
        self.console_button.place(relx=1.0, rely=1.0, anchor="se")

    def get_tag_suggestions(self, query):
        url = f"https://e621.net/tags/autocomplete.json?search[name_matches]={query}&expiry=7"
        response = requests.get(url)
        if response.status_code == 200:
            tags = response.json()
            self.computed_tags_listbox.delete(0, tk.END)
            for tag in tags:
                tag_name = tag.get("name", "Unknown Tag")
                post_count = tag.get("post_count", 0)
                self.computed_tags_listbox.insert(tk.END, f"{tag_name} ({post_count} posts)")
        else:
            print("Failed to fetch data")

    def async_update_tag_suggestions(self, query):
        self.get_tag_suggestions(query)

    def compute_query_tags(self):
        query = self.tags_entry.get().strip()
        if not query:
            return ""
        print(f"CQT: {query}")
        threading.Thread(target=self.async_update_tag_suggestions, args=(query,), daemon=True).start()
        return query

    def auto_correct_tags(self, tags):
        corrections = {"catgirl": "cat girl", "doggo": "dog"}
        words = tags.split()
        corrected = [corrections.get(word.lower(), word) for word in words]
        corrected_tags = " ".join(corrected)
        if corrected_tags != tags:
            self.log(f"Auto-corrected search: '{tags}' -> '{corrected_tags}'")
            self.tags_entry.delete(0, tk.END)
            self.tags_entry.insert(0, corrected_tags)
        return corrected_tags

    def log_in(self):
        dlg = LoginDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            self.username, self.api_key = dlg.result
            self.log(f"Logged in as {self.username}")
        else:
            self.log("Login cancelled.")

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def cheatsheet(self):
        webbrowser.open("https://e621.net/help/cheatsheet")

    def start_preview_thread(self):
        self.stop_preview = False
        self.preview_button.config(state="disabled")
        query_tags = self.compute_query_tags()
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.preview_images.clear()
        preview_count = self.preview_count_entry.get().strip()
        debug = self.debug_var.get()
        try:
            count = int(preview_count)
        except ValueError:
            messagebox.showwarning("Input Error", "Preview count must be a number.")
            self.preview_button.config(state="normal")
            return
        thread = threading.Thread(target=self.load_preview, args=(query_tags, count, debug))
        thread.start()

    def stop_preview_loading(self):
        self.stop_preview = True

    def load_preview(self, query_tags, count, debug):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.fetch_and_show_preview(query_tags, count, debug))
        loop.close()

    async def fetch_and_show_preview(self, query_tags, limit, debug):
        self.PreviewText.set("Loading...")
        url = BASE_URL.format(query_tags, limit)
        if debug:
            print(f"[DEBUG] Preview URL: {url}")
        auth = None
        if self.username and self.api_key:
            auth = aiohttp.BasicAuth(self.username, self.api_key)

        async with aiohttp.ClientSession(auth=auth) as session:
            data = await get_json(url, session, debug)
            if not data or "posts" not in data:
                self.after(0, lambda: messagebox.showerror("Error", "No data received."))
                self.after(0, lambda: self.preview_button.config(state="normal"))
                return

            posts = data["posts"]
            col = 0
            row = 0
            for post in posts:
                if self.stop_preview:
                    if debug:
                        print("[DEBUG] Preview loading stopped by user.")
                    break

                sample = post.get("sample")
                image_url = sample["url"] if sample and sample.get("url") else post["file"].get("url")
                full_url = post["file"].get("url")
                if not image_url or not full_url:
                    continue
                tags = post.get("tags", {})
                artist_tags = tags.get("artist", [])
                artist = artist_tags[0] if artist_tags else "unknown"
                post_id = post.get("id", "N/A")
                if post_id not in self.vote_data:
                    self.vote_data[post_id] = {"votes": 0, "favourite": False, "fav_count": 0, "artist": artist}
                details = await fetch_post_details(post_id, session, auth, debug)
                if details is not None:
                    total_votes, fav, fav_count = details
                    self.vote_data[post_id] = {"votes": total_votes, "favourite": fav, "fav_count": fav_count, "artist": artist}
                try:
                    async with session.get(image_url, headers=HEADERS, auth=auth) as resp:
                        if resp.status == 200:
                            data = await resp.read()
                            original_image = Image.open(io.BytesIO(data))
                            thumb = original_image.copy()
                            thumb.thumbnail((150, 150))
                            photo = ImageTk.PhotoImage(thumb)
                            self.after(0, self.add_preview_image, photo, row, col, full_url, original_image, artist, post_id)
                            col += 1
                            if col >= 4:
                                col = 0
                                row += 1
                        else:
                            if debug:
                                print(f"[DEBUG] Failed to fetch preview image. HTTP {resp.status}")
                except Exception as e:
                    if debug:
                        print(f"[DEBUG] Exception in preview: {e}")

        self.PreviewText.set("Finished!")
        time.sleep(1.5)
        self.PreviewText.set("Preview")
        self.after(0, lambda: self.preview_button.config(state="normal"))

    def add_preview_image(self, photo, row, col, full_url, original_image, Aartist, post_id):
        vote_info = self.vote_data.get(post_id, {"votes": 0, "favourite": False, "fav_count": 0, "artist": Aartist})
        self.preview_images.append(photo)
        frame = ttk.Frame(self.scrollable_frame, relief=tk.RAISED, borderwidth=1)
        frame.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")
        image_label = ttk.Label(frame, image=photo)
        image_label.pack()
        info_text = (
            f"Artist: {vote_info.get('artist', Aartist)}\n"
            f"Post: {post_id}\n"
            f"Votes: {vote_info.get('votes', 0)}\n"
            f"Favourites: {vote_info.get('fav_count', 0)}\n"
            f"Your Favourite: {'Yes' if vote_info.get('favourite', False) else 'No'}"
        )
        info_label = ttk.Label(frame, text=info_text, background="#ffffff", foreground="#000000", font=("Segoe UI", 9))
        info_label.pack(fill="x")
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=2)
        upvote_btn = ttk.Button(btn_frame, text="Upvote", command=lambda pid=post_id, il=info_label: self.upvote_post(pid, il))
        upvote_btn.pack(side="left", padx=2)
        fav_btn = ttk.Button(btn_frame, text="Favourite", command=lambda pid=post_id, il=info_label: self.favourite_post(pid, il))
        fav_btn.pack(side="left", padx=2)
        frame.bind("<Button-1>", lambda event, url=full_url, orig=original_image, artist=Aartist, pid=post_id: self.show_full_image(url, orig, artist, pid))
        image_label.bind("<Button-1>", lambda event, url=full_url, orig=original_image, artist=Aartist, pid=post_id: self.show_full_image(url, orig, artist, pid))

    def upvote_post(self, post_id, info_label):
        if not self.username:
            messagebox.showwarning("Login Required", "Please log in to upvote.")
            return
        def do_vote():
            try:
                new_votes = upvote_post_api(self.username, self.api_key, post_id)
                if new_votes is not None:
                    self.vote_data[post_id]["votes"] = new_votes
                else:
                    self.vote_data[post_id]["votes"] += 1
                self.log(f"Post {post_id} upvoted by {self.username}.")
                self.update_post_details_sync(post_id)
            except Exception as e:
                self.log(f"Error upvoting post {post_id}: {e}")
            self.update_info_label(post_id, info_label)
        threading.Thread(target=do_vote).start()

    def favourite_post(self, post_id, info_label):
        if not self.username:
            messagebox.showwarning("Login Required", "Please log in to favourite.")
            return
        def do_fav():
            try:
                if not self.vote_data[post_id]["favourite"]:
                    fav_status = favourite_post_api(self.username, self.api_key, post_id, create=True)
                    self.vote_data[post_id]["favourite"] = fav_status
                    self.log(f"Post {post_id} favourited by {self.username}.")
                else:
                    fav_status = favourite_post_api(self.username, self.api_key, post_id, create=False)
                    self.vote_data[post_id]["favourite"] = fav_status
                    self.log(f"Post {post_id} unfavourited by {self.username}.")
                self.update_post_details_sync(post_id)
            except Exception as e:
                self.log(f"Error favouriting post {post_id}: {e}")
            self.update_info_label(post_id, info_label)
        threading.Thread(target=do_fav).start()

    def update_post_details_sync(self, post_id):
        try:
            url = f"https://e621.net/posts/{post_id}.json"
            auth = (self.username, self.api_key)
            r = requests.get(url, auth=auth, headers=HEADERS)
            if r.status_code == 200:
                data = r.json().get("post", {})
                score = data.get("score", {})
                total_votes = score.get("total", 0)
                fav = data.get("has_favorited", False)
                fav_count = data.get("fav_count", 0)
                artist = self.vote_data.get(post_id, {}).get("artist", "unknown")
                self.vote_data[post_id] = {"votes": total_votes, "favourite": fav, "fav_count": fav_count, "artist": artist}
            else:
                self.log(f"Failed to update details for post {post_id}: HTTP {r.status_code}")
        except Exception as e:
            self.log(f"Exception updating post {post_id}: {e}")

    def update_info_label(self, post_id, info_label):
        vote_info = self.vote_data.get(post_id, {"votes": 0, "favourite": False, "fav_count": 0, "artist": "unknown"})
        current_text = (
            f"Artist: {vote_info.get('artist', 'unknown')}\n"
            f"Post: {post_id}\n"
            f"Votes: {vote_info.get('votes', 0)}\n"
            f"Favourites: {vote_info.get('fav_count', 0)}\n"
            f"Your Favourite: {'Yes' if vote_info.get('favourite', False) else 'No'}"
        )
        info_label.config(text=current_text)

    def show_full_image(self, url, original_image, artist, post_id):
        ext = url.split('.')[-1].lower()
        if ext in ['mp4', 'webm', 'mov', 'avi']:
            messagebox.showinfo("Video not supported", "Video files are not supported. Please download them and play them with VLC or a similar player.")
            return
        top = tk.Toplevel(self)
        vote_info = self.vote_data.get(post_id, {"votes": 0, "favourite": False, "fav_count": 0})
        top.title(f"Artist: {artist} | Post: {post_id} | Votes: {vote_info.get('votes',0)} | Fav: {vote_info.get('fav_count',0)} | Your Fav: {'Yes' if vote_info.get('favourite', False) else 'No'}")
        top.geometry("250x250")
        image_label = ttk.Label(top)
        image_label.pack(expand=True, fill=tk.BOTH)
        top.original_image = original_image.copy()
        def update_image(event=None):
            new_width = top.winfo_width()
            new_height = top.winfo_height()
            if new_width > 1 and new_height > 1:
                resized = top.original_image.resize((new_width, new_height), Image.LANCZOS)
                photo = ImageTk.PhotoImage(resized)
                image_label.config(image=photo)
                image_label.image = photo
        top.bind("<Configure>", update_image)
        update_image()

    def open_download_dialog(self):
        if self.compute_query_tags() == "":
            query_tags = ""
        else:
            query_tags = self.compute_query_tags()
        dlg = DownloadDialog(self, query_tags)
        self.wait_window(dlg)
        if dlg.result:
            thread_count, image_count, folder_name, zip_choice = dlg.result
            tags = self.tags_entry.get().strip()
            if not tags:
                messagebox.showwarning("Input Error", "Please enter tags before downloading.")
                return
            debug = self.debug_var.get()
            if self.compute_query_tags() == "":
                query_tags = ""
            else:
                query_tags = self.compute_query_tags()
            thread = threading.Thread(target=self.run_scraper_thread, args=(query_tags, image_count, thread_count, folder_name, zip_choice, debug))
            thread.start()

    def run_scraper_thread(self, query_tags, image_count, thread_count, folder_name, zip_choice, debug):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        auth = None
        if self.username and self.api_key:
            auth = aiohttp.BasicAuth(self.username, self.api_key)

        loop.run_until_complete(self.run_scraper(query_tags, image_count, thread_count, folder_name, zip_choice, debug, auth))
        loop.close()

    async def run_scraper(self, query_tags, image_count, thread_count, folder_name, zip_choice, debug=False, auth=None):
        download_folder = os.path.join("Folders", folder_name)
        os.makedirs(download_folder, exist_ok=True)

        if debug:
            print(f"[DEBUG] Starting scraper: threads={thread_count}, images={image_count}")
            print(f"[DEBUG] Download folder: {download_folder}")
            print(f"[DEBUG] Query Tags: {query_tags}")
        await start_scraper(
            query_tags=query_tags,
            total_images=image_count,
            thread_limit=thread_count,
            download_folder=download_folder,
            debug=debug,
            job_callback=lambda pid, status: self.update_job_status(pid, status),
            auth=auth
        )

        if zip_choice:
            zip_folder(download_folder, download_folder + ".zip")
            if debug:
                print("[DEBUG] Folder zipped.")

        self.after(0, lambda: messagebox.showinfo("Done", "Scraping completed."))

    def update_job_status(self, post_id, status):
        if post_id in self.job_map:
            index = self.job_map[post_id]
            self.job_listbox.delete(index)
            self.job_listbox.insert(index, f"{post_id}: {status}")
        else:
            self.job_listbox.insert(tk.END, f"{post_id}: {status}")
        self.job_map[post_id] = self.job_listbox.size() - 1

    def show_console_window(self):
        if hasattr(self, 'console_window') and self.console_window is not None:
            self.console_window.lift()
            return
        self.console_window = tk.Toplevel(self)
        self.console_window.title("Console Output")
        self.console_text = tk.Text(self.console_window, wrap="word", bg="#3c3f41", fg="#e0e0e0", font=("Segoe UI", 10))
        self.console_text.pack(expand=True, fill="both")
        self.console_window.protocol("WM_DELETE_WINDOW", self.close_console_window)
        self.update_console_text()

    def update_console_text(self):
        if hasattr(self, 'console_text'):
            self.console_text.delete("1.0", tk.END)
            self.console_text.insert(tk.END, self.console_redirector.get_buffer())
        self.after(1000, self.update_console_text)

    def close_console_window(self):
        self.console_window.destroy()
        self.console_window = None
class DownloadDialog(tk.Toplevel):
    def __init__(self, parent, query_tags):
        super().__init__(parent)
        self.title("Download Options")
        self.resizable(False, False)
        self.result = None
        ttk.Label(self, text="Threads:").grid(row=0, column=0, padx=10, pady=5)
        self.thread_entry = ttk.Entry(self, width=10)
        self.thread_entry.grid(row=0, column=1, padx=10, pady=5)
        self.thread_entry.insert(0, "5")
        ttk.Label(self, text="Image Count:").grid(row=1, column=0, padx=10, pady=5)
        self.image_count_entry = ttk.Entry(self, width=10)
        self.image_count_entry.grid(row=1, column=1, padx=10, pady=5)
        self.image_count_entry.insert(0, "10")
        ttk.Label(self, text="Folder Name:").grid(row=2, column=0, padx=10, pady=5)
        self.folder_entry = ttk.Entry(self, width=20)
        self.folder_entry.grid(row=2, column=1, padx=10, pady=5)
        self.folder_entry.insert(0, query_tags.replace(" ", "_").replace(":", "-"))
        self.zip_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text="Zip Folder", variable=self.zip_var).grid(row=3, columnspan=2, padx=10, pady=5)
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=4, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="OK", command=self.on_ok).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side="left", padx=5)

    def on_ok(self):
        try:
            thread_count = int(self.thread_entry.get())
            image_count = int(self.image_count_entry.get())
            folder_name = self.folder_entry.get().strip()
            zip_choice = self.zip_var.get()
            self.result = (thread_count, image_count, folder_name, zip_choice)
            self.destroy()
        except Exception as e:
            messagebox.showerror("Input Error", str(e))

if __name__ == "__main__":
    app = ViewerDownloaderApp()
    app.mainloop()
