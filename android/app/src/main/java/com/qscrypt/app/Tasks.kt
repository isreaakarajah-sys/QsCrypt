package com.qscrypt.app

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import java.io.File
import org.json.JSONArray
import org.json.JSONObject

/** Builders for the background jobs the screens start. */

private fun fail(code: String, message: String = "") = Reply(JSONObject().put("ok", false).put("code", code).put("message", message).toString())

private fun okReply(summary: String) = Reply(JSONObject().put("ok", true).put("summary", summary).toString())

fun childOf(dir: String, name: String) = if (dir == "/" || dir.isEmpty()) "/$name" else "${dir.trimEnd('/')}/$name"

/** Filling the free space of a quick-formatted volume with encrypted data, resumably. */
object Fill {
    // Small steps: the vault stays responsive and pausing takes effect within a second or two.
    private const val STEP = 16L shl 20

    /** Whether this volume can be filled (not read-only, not an outer volume with a protected hidden one). */
    fun possible(s: Session): Boolean = !s.info.readOnly && !s.info.protected && !s.plain && s.info.fs != "NTFS"

    fun pending(s: Session): Boolean = Prefs.fillCursor(s.stableKey) >= 0

    fun running(s: Session): Jobs.Job? = Jobs.list.firstOrNull { it.active && it.kind == "fill" && s.handle in it.vaults }

    /** Remembers that the volume needs filling, and starts. */
    fun schedule(context: Context, s: Session): Jobs.Job? {
        if (!possible(s)) return null
        if (Prefs.fillCursor(s.stableKey) < 0) Prefs.setFillCursor(s.stableKey, 0)
        return start(context, s)
    }

    /** Continues an unfinished fill when its volume is opened again. */
    fun resumeFor(context: Context, s: Session) {
        if (pending(s) && possible(s) && running(s) == null) start(context, s)
    }

    fun start(context: Context, s: Session): Jobs.Job {
        running(s)?.let { return it }
        val key = s.stableKey
        val name = s.container.name.substringBeforeLast('.').ifBlank { s.container.name }
        return Jobs.start(context, "fill", "ملء المساحة الفارغة · $name", listOf(s.handle)) work@{
            var cursor = Prefs.fillCursor(key).coerceAtLeast(0)
            detail("تُكتب بيانات مشفّرة في المساحة غير المستخدمة، فلا يُعرف ما كُتب في القرص")
            while (true) {
                if (!checkpoint()) return@work fail("cancelled")
                if (AppState.session(s.handle) == null) return@work fail("invalid_argument", "the vault is closed")
                val r = Call("vault.zeroFree").put("handle", s.handle).put("cursor", cursor).put("max", STEP).run()
                if (!r.ok) return@work r
                cursor = r.json.optLong("cursor")
                val total = r.json.optLong("total")
                job.total = total
                job.done = cursor.coerceAtMost(total)
                Prefs.setFillCursor(key, cursor)
                progress().onProgress(job.done, total)
                if (r.json.optBoolean("done")) break
            }
            Prefs.clearFill(key)
            okReply("مُلئت المساحة الفارغة ببيانات مشفّرة.")
        }
    }
}

/** One item to copy: a file or a folder in a vault. */
data class Item(val name: String, val dir: Boolean, val size: Long)

object Transfers {
    /**
     * Copies (or moves) items of a folder of one vault into a folder of the
     * same or another vault. Resumable after a restart: files already there
     * with the same size are skipped.
     */
    fun copy(context: Context, from: Session, dir: String, names: List<String>, to: Session, dest: String, move: Boolean, resume: Boolean = false, uid: String = "", onEnd: ((Jobs.Job) -> Unit)? = null): Jobs.Job {
        val spec = JSONObject()
            .put("uid", uid.ifEmpty { System.currentTimeMillis().toString() })
            .put("src", from.stableKey).put("srcName", from.container.name).put("dir", dir)
            .put("names", JSONArray(names))
            .put("dst", to.stableKey).put("dstName", to.container.name).put("dest", dest)
            .put("move", move)
        val verb = if (move) "نقل" else "نسخ"
        val what = if (names.size == 1) "«${names[0]}»" else "${names.size} عناصر"
        val title = "$verb $what إلى ${to.container.name.substringBeforeLast('.')}"
        val sameVault = from.handle == to.handle
        val spool = context.cacheDir.absolutePath
        return Jobs.start(context, "copy", title, listOf(from.handle, to.handle).distinct(), spec, onEnd) work@{
            // Sizes first, for one progress bar over everything. When resuming a
            // move, items already moved (gone from the source) are done.
            var total = 0L
            val todo = mutableListOf<String>()
            val sizes = mutableListOf<Long>()
            for (n in names) {
                val r = Call("fs.tree").put("handle", from.handle).put("path", childOf(dir, n)).run()
                if (!r.ok) {
                    if (resume && move && r.code == "not_found") continue
                    return@work r
                }
                todo += n
                sizes += r.json.optLong("total").also { total += it }
            }
            job.total = total
            var base = 0L
            var copied = 0
            for ((i, n) in todo.withIndex()) {
                if (!checkpoint()) return@work fail("cancelled")
                detail(n)
                val src = childOf(dir, n)
                if (sameVault && move) {
                    // Inside one vault a move only rewrites folder entries.
                    val r = Call("fs.move").put("handle", from.handle).put("path", src).put("dest", dest).run()
                    if (!r.ok) return@work r
                } else {
                    val r = Call("fs.copy").put("from", from.handle).put("path", src).put("to", to.handle).put("dest", dest)
                        .put("existing", if (resume) "resume" else "fail").put("spool", spool)
                        .run(progress(base, total))
                    if (!r.ok) return@work r
                    if (move) {
                        val d = Reply(QsCore.remove(from.handle, src))
                        if (!d.ok) return@work d
                    }
                }
                base += sizes[i]
                copied++
                job.done = base
            }
            okReply(if (move) "نُقل $copied ${if (copied == 1) "عنصر" else "عناصر"}." else "نُسخ $copied ${if (copied == 1) "عنصر" else "عناصر"}.")
        }
    }

    /** Resumes a job remembered from before a restart, once its vaults are open. */
    fun resume(context: Context, p: Jobs.Pending): String? = when (p.kind) {
        "copy" -> resumeCopy(context, p)
        "phoneImport", "phoneExport", "importDocs", "exportTree" -> resumeTransfer(context, p)
        else -> "لا يمكن استئناف هذه العملية."
    }

    private fun session(key: String): Session? = AppState.sessions.firstOrNull { it.stableKey == key }

    private fun resumeTransfer(context: Context, p: Jobs.Pending): String? {
        val s = p.spec
        val vaultKey = s.optString(if (p.kind == "phoneImport" || p.kind == "importDocs") "dst" else "src")
        val vaultName = s.optString(if (p.kind == "phoneImport" || p.kind == "importDocs") "dstName" else "srcName")
        val v = session(vaultKey) ?: return "افتح «$vaultName» أولاً."
        if (p.kind == "phoneImport" || p.kind == "phoneExport") {
            if (!PhoneFiles.hasAccess(context)) return "اسمح للتطبيق بالوصول إلى ملفات الهاتف أولاً (تبويب ملفاتي)."
        }
        Jobs.dropPending(p)
        val uid = s.optString("uid")
        when (p.kind) {
            "phoneImport" -> {
                val arr = s.optJSONArray("paths") ?: JSONArray()
                importPhone(context, v, s.optString("dest", "/"), (0 until arr.length()).map { arr.getString(it) }, s.optBoolean("move"), s.optString("title").ifEmpty { null }, resume = true, uid = uid)
            }
            "phoneExport" -> exportPhone(context, v, s.optString("dir", "/"), items(s), s.optString("dest"), s.optBoolean("move"), resume = true, uid = uid)
            "importDocs" -> {
                val arr = s.optJSONArray("docs") ?: JSONArray()
                val docs = (0 until arr.length()).map { i -> arr.getJSONObject(i).let { Doc(Uri.parse(it.optString("uri")), it.optString("name"), it.optLong("size")) } }
                importDocs(context, v, s.optString("dir", "/"), docs, resumeFrom = s.optInt("done"), uid = uid)
            }
            "exportTree" -> exportTo(context, v, s.optString("dir", "/"), items(s), Uri.parse(s.optString("tree")), resumeFrom = s.optInt("done"), uid = uid)
        }
        return null
    }

    private fun items(s: JSONObject): List<Item> {
        val arr = s.optJSONArray("items") ?: JSONArray()
        return (0 until arr.length()).map { i -> arr.getJSONObject(i).let { Item(it.optString("name"), it.optBoolean("dir"), it.optLong("size")) } }
    }

    private fun itemsJson(items: List<Item>) = JSONArray().apply { items.forEach { put(JSONObject().put("name", it.name).put("dir", it.dir).put("size", it.size)) } }

    private fun resumeCopy(context: Context, p: Jobs.Pending): String? {
        val s = p.spec
        val from = AppState.sessions.firstOrNull { it.stableKey == s.optString("src") } ?: return "افتح «${s.optString("srcName")}» أولاً."
        val to = AppState.sessions.firstOrNull { it.stableKey == s.optString("dst") } ?: return "افتح «${s.optString("dstName")}» أولاً."
        val arr = s.optJSONArray("names") ?: JSONArray()
        val names = (0 until arr.length()).map { arr.getString(it) }
        Jobs.dropPending(p)
        copy(context, from, s.optString("dir", "/"), names, to, s.optString("dest", "/"), s.optBoolean("move"), resume = true, uid = s.optString("uid"))
        return null
    }

    /** "name (2).ext" until it is free. */
    private fun freeName(name: String, taken: Set<String>): String {
        val base = name.substringBeforeLast('.', name)
        val ext = if (name.contains('.')) "." + name.substringAfterLast('.') else ""
        for (n in 1..999) {
            val candidate = if (n == 1) name else "$base ($n)$ext"
            if (candidate !in taken) return candidate
        }
        return name
    }

    private fun names(handle: Long, dir: String): MutableSet<String> {
        val r = Reply(QsCore.list(handle, dir))
        return parseEntries(r.json).map { it.name }.toMutableSet()
    }

    /** A document picked on the device, with its name and size. */
    data class Doc(val uri: Uri, val name: String, val size: Long)

    /**
     * Adds documents from the device to a vault folder ("name (2)" if taken).
     * Resumable after a restart: the documents' access is kept, and the job
     * remembers how many are done.
     */
    fun importDocs(context: Context, s: Session, dir: String, docs: List<Doc>, onEnd: ((Jobs.Job) -> Unit)? = null, resumeFrom: Int = 0, uid: String = ""): Jobs.Job {
        if (resumeFrom == 0) docs.forEach { Saf.persist(context, it.uri) }
        val spec = JSONObject().put("uid", uid.ifEmpty { System.currentTimeMillis().toString() })
            .put("dst", s.stableKey).put("dstName", s.container.name).put("dir", dir).put("done", resumeFrom)
            .put("docs", JSONArray().apply { docs.forEach { put(JSONObject().put("uri", it.uri.toString()).put("name", it.name).put("size", it.size)) } })
        val title = if (docs.size == 1) "إضافة «${docs[0].name}»" else "إضافة ${docs.size} ملفات"
        return Jobs.start(context, "importDocs", title, listOf(s.handle), spec, onEnd) work@{
            val total = docs.sumOf { it.size.coerceAtLeast(0) }
            job.total = total
            val taken = names(s.handle, dir)
            var base = docs.take(resumeFrom).sumOf { it.size.coerceAtLeast(0) }
            for ((i, d) in docs.withIndex()) {
                if (i < resumeFrom) continue
                if (!checkpoint()) return@work fail("cancelled")
                detail("${i + 1}/${docs.size} · ${d.name}")
                val name = freeName(d.name, taken)
                val pfd = Saf.open(context, d.uri, "r") ?: return@work fail("io", "cannot open ${d.name}")
                val r = pfd.use { Reply(QsCore.importFile(s.handle, it.fd, d.size, childOf(dir, name), false, progress(base, total))) }
                if (!r.ok) return@work Reply(r.json.put("message", "«${d.name}»: " + r.json.optString("message")).toString())
                taken += name
                base += d.size.coerceAtLeast(0)
                spec.put("done", i + 1)
                Jobs.save()
            }
            docs.forEach { Saf.release(context, it.uri) }
            okReply(if (docs.size == 1) "أُضيف «${docs[0].name}» مشفّراً." else "أُضيف ${docs.size} ملفات مشفّرة.")
        }
    }

    private data class TreeNode(val uri: Uri, val name: String, val dir: Boolean, val size: Long, val children: List<TreeNode>)

    private fun walkTree(context: Context, tree: Uri, docId: String, name: String, depth: Int = 0): TreeNode {
        val children = mutableListOf<TreeNode>()
        val kids = DocumentsContract.buildChildDocumentsUriUsingTree(tree, docId)
        val cols = arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME, DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_SIZE)
        runCatching {
            context.contentResolver.query(kids, cols, null, null, null)?.use { c ->
                while (c.moveToNext()) {
                    val id = c.getString(0)
                    val n = c.getString(1) ?: continue
                    val isDir = c.getString(2) == DocumentsContract.Document.MIME_TYPE_DIR
                    val size = if (c.isNull(3)) 0L else c.getLong(3)
                    if (isDir && depth < 32) children += walkTree(context, tree, id, n, depth + 1)
                    else if (!isDir) children += TreeNode(DocumentsContract.buildDocumentUriUsingTree(tree, id), n, false, size, emptyList())
                }
            }
        }
        return TreeNode(DocumentsContract.buildDocumentUriUsingTree(tree, docId), name, true, 0, children)
    }

    private fun sizeOf(n: TreeNode): Long = if (n.dir) n.children.sumOf { sizeOf(it) } else n.size

    private fun countFiles(n: TreeNode): Int = if (n.dir) n.children.sumOf { countFiles(it) } else 1

    /** Adds a whole folder from the device (picked with OpenDocumentTree), with its subfolders. */
    fun importFolder(context: Context, s: Session, dir: String, tree: Uri, onEnd: ((Jobs.Job) -> Unit)? = null): Jobs.Job {
        val rootName = Saf.treeName(context, tree)
        return Jobs.start(context, "import", "إضافة المجلد «$rootName»", listOf(s.handle), onEnd = onEnd) work@{
            detail("قراءة محتوى المجلد…")
            val root = walkTree(context, tree, DocumentsContract.getTreeDocumentId(tree), rootName)
            val total = sizeOf(root)
            job.total = total
            var base = 0L
            var files = 0
            val top = freeName(rootName, names(s.handle, dir))
            suspend fun add(n: TreeNode, into: String): Reply? {
                if (!checkpoint()) return fail("cancelled")
                if (n.dir) {
                    val path = childOf(into, if (into == dir) top else n.name)
                    val m = Reply(QsCore.mkdir(s.handle, path))
                    if (!m.ok && m.code != "exists") return m
                    for (c in n.children) add(c, path)?.let { return it }
                    return null
                }
                detail(n.name)
                val pfd = Saf.open(context, n.uri, "r") ?: return fail("io", "cannot open ${n.name}")
                val r = pfd.use { Reply(QsCore.importFile(s.handle, it.fd, n.size, childOf(into, n.name), true, progress(base, total))) }
                if (!r.ok) return Reply(r.json.put("message", "«${n.name}»: " + r.json.optString("message")).toString())
                base += n.size
                files++
                return null
            }
            add(root, dir)?.let { return@work it }
            okReply("أُضيف المجلد «$rootName» ($files ${if (files == 1) "ملف" else "ملفات"}) مشفّراً.")
        }
    }

    /** A child of a SAF folder by name (to reuse folders a resumed export already made). */
    private fun childDoc(context: Context, tree: Uri, parent: Uri, name: String): Uri? = runCatching {
        val kids = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getDocumentId(parent))
        context.contentResolver.query(kids, arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)?.use { c ->
            while (c.moveToNext()) if (c.getString(1) == name) return@runCatching DocumentsContract.buildDocumentUriUsingTree(tree, c.getString(0))
            null
        }
    }.getOrNull()

    /**
     * Exports items (files and folders) to a folder on the device picked with
     * OpenDocumentTree. Resumable after a restart: files are written in a fixed
     * order and the job remembers how many are done.
     */
    fun exportTo(context: Context, s: Session, dir: String, items: List<Item>, tree: Uri, onEnd: ((Jobs.Job) -> Unit)? = null, resumeFrom: Int = 0, uid: String = ""): Jobs.Job {
        if (resumeFrom == 0) Saf.persist(context, tree)
        val spec = JSONObject().put("uid", uid.ifEmpty { System.currentTimeMillis().toString() })
            .put("src", s.stableKey).put("srcName", s.container.name).put("dir", dir).put("done", resumeFrom)
            .put("items", itemsJson(items)).put("tree", tree.toString())
        val title = if (items.size == 1) "تصدير «${items[0].name}»" else "تصدير ${items.size} عناصر"
        return Jobs.start(context, "exportTree", title, listOf(s.handle), spec, onEnd) work@{
            var total = 0L
            for (it in items) {
                val r = Call("fs.tree").put("handle", s.handle).put("path", childOf(dir, it.name)).run()
                if (r.ok) total += r.json.optLong("total")
            }
            job.total = total
            var base = 0L
            var files = 0
            val root = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
            suspend fun out(path: String, name: String, isDir: Boolean, size: Long, parent: Uri): Reply? {
                if (!checkpoint()) return fail("cancelled")
                if (isDir) {
                    val folder = (if (resumeFrom > 0) childDoc(context, tree, parent, name) else null)
                        ?: runCatching { DocumentsContract.createDocument(context.contentResolver, parent, DocumentsContract.Document.MIME_TYPE_DIR, name) }.getOrNull()
                        ?: return fail("io", "cannot create the folder $name")
                    for (e in parseEntries(Reply(QsCore.list(s.handle, path)).json)) {
                        out(childOf(path, e.name), e.name, e.dir, e.size, folder)?.let { return it }
                    }
                    return null
                }
                if (files < resumeFrom) {
                    // Written before the restart.
                    base += size
                    files++
                    return null
                }
                detail(name)
                (if (files == resumeFrom && resumeFrom > 0) childDoc(context, tree, parent, name) else null)?.let { Saf.delete(context, it) }   // the one cut short
                val doc = runCatching { DocumentsContract.createDocument(context.contentResolver, parent, "application/octet-stream", name) }.getOrNull()
                    ?: return fail("io", "cannot create $name")
                val pfd = Saf.open(context, doc, "w") ?: return fail("io", "cannot write $name")
                val r = pfd.use { Reply(QsCore.exportFile(s.handle, path, it.fd, progress(base, total))) }
                if (!r.ok) {
                    Saf.delete(context, doc)
                    return r
                }
                base += size
                files++
                spec.put("done", files)
                Jobs.save()
                return null
            }
            for (it in items) out(childOf(dir, it.name), it.name, it.dir, it.size, root)?.let { r -> return@work r }
            Saf.release(context, tree)
            okReply("صُدّر $files ${if (files == 1) "ملف" else "ملفات"}. تذكّر أن النسخ المصدّرة غير مشفّرة.")
        }
    }

    // ---------------------------------------------------------------- phone files

    /**
     * Encrypts files and folders of the phone's storage into a vault folder,
     * keeping their folder structure. With [move], each original is deleted as
     * soon as its encrypted copy is written. Resumable after a restart: what is
     * already in the vault with the same size is skipped (and, for a move,
     * originals already deleted are done).
     */
    fun importPhone(context: Context, s: Session, dir: String, paths: List<String>, move: Boolean, title: String? = null, resume: Boolean = false, uid: String = "", onEnd: ((Jobs.Job) -> Unit)? = null): Jobs.Job {
        val spec = JSONObject().put("uid", uid.ifEmpty { System.currentTimeMillis().toString() })
            .put("dst", s.stableKey).put("dstName", s.container.name).put("dest", dir)
            .put("paths", JSONArray(paths)).put("move", move).put("title", title ?: "")
        val tops = paths.map(::File)
        val label = title ?: (if (move) "نقل " else "تشفير ") + (if (tops.size == 1) "«${tops[0].name}»" else "${tops.size} عناصر") + " إلى ${s.container.name.substringBeforeLast('.')}"
        return Jobs.start(context, "phoneImport", label, listOf(s.handle), spec, onEnd) work@{
            detail("قراءة الملفات…")
            val present = tops.filter { it.exists() }
            val owner = HashMap<String, File>()
            val all = mutableListOf<File>()
            for (t in present) PhoneFiles.walk(listOf(t)).forEach { f -> owner[f.absolutePath] = t; all += f }
            val total = all.sumOf { it.length() }
            job.total = total
            val listed = HashMap<String, Map<String, Entry>>()
            fun existing(vdir: String): Map<String, Entry> = listed.getOrPut(vdir) { parseEntries(Reply(QsCore.list(s.handle, vdir)).json).associateBy { it.name } }
            // New items get a free name at the top; a resumed job merges into what it made.
            val taken = existing(dir).keys.toMutableSet()
            val topName = present.associate { t -> t.absolutePath to (if (resume) t.name else freeName(t.name, taken).also { taken += it }) }
            val made = mutableSetOf("/")
            fun ensureDir(v: String): Reply? {
                if (v in made) return null
                val parent = v.substringBeforeLast('/').ifEmpty { "/" }
                ensureDir(parent)?.let { return it }
                val m = Reply(QsCore.mkdir(s.handle, v))
                if (!m.ok && m.code != "exists") return m
                made += v
                listed.remove(parent)
                return null
            }
            ensureDir(dir)?.let { return@work it }
            var base = 0L
            var done = 0
            for (f in all) {
                if (!checkpoint()) return@work fail("cancelled")
                val top = owner[f.absolutePath]!!
                val rel = f.absolutePath.removePrefix(top.absolutePath).trimStart('/')
                val name = topName[top.absolutePath]!!
                val vpath = if (rel.isEmpty()) childOf(dir, name) else childOf(childOf(dir, name), rel)
                val vdir = vpath.substringBeforeLast('/').ifEmpty { "/" }
                ensureDir(vdir)?.let { return@work it }
                val size = f.length()
                val have = existing(vdir)[f.name]
                if (have == null || have.dir || have.size != size) {
                    detail("${done + 1}/${all.size} · ${f.name}")
                    val pfd = runCatching { ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY) }.getOrNull()
                        ?: return@work fail("io", "cannot open ${f.name}")
                    val r = pfd.use { Reply(QsCore.importFile(s.handle, it.fd, size, vpath, true, progress(base, total))) }
                    if (!r.ok) return@work Reply(r.json.put("message", "«${f.name}»: " + r.json.optString("message")).toString())
                    listed.remove(vdir)
                }
                if (move && f.delete()) PhoneFiles.rescan(listOf(f))
                base += size
                done++
                job.done = base
            }
            // Folders emptied by a move go too.
            if (move) present.filter { it.isDirectory }.forEach { it.deleteRecursively() }
            val n = "$done ${if (done == 1) "ملف" else "ملفات"}"
            okReply(if (move) "شُفّر $n ونُقل إلى الخزنة، وحُذفت الأصول من الهاتف." else "شُفّر $n داخل الخزنة. الأصول ما زالت على الهاتف.")
        }
    }

    /**
     * Writes vault items into a folder on the phone (decrypted copies). With
     * [move], they are removed from the vault afterwards. Resumable: files
     * already on the phone with the same size are skipped.
     */
    fun exportPhone(context: Context, s: Session, dir: String, items: List<Item>, dest: String, move: Boolean, resume: Boolean = false, uid: String = "", onEnd: ((Jobs.Job) -> Unit)? = null): Jobs.Job {
        val spec = JSONObject().put("uid", uid.ifEmpty { System.currentTimeMillis().toString() })
            .put("src", s.stableKey).put("srcName", s.container.name).put("dir", dir)
            .put("items", itemsJson(items)).put("dest", dest).put("move", move)
        val title = (if (move) "نقل " else "نسخ ") + (if (items.size == 1) "«${items[0].name}»" else "${items.size} عناصر") + " إلى الهاتف"
        return Jobs.start(context, "phoneExport", title, listOf(s.handle), spec, onEnd) work@{
            var total = 0L
            for (it in items) {
                val r = Call("fs.tree").put("handle", s.handle).put("path", childOf(dir, it.name)).run()
                if (r.ok) total += r.json.optLong("total")
            }
            job.total = total
            var base = 0L
            var files = 0
            val written = mutableListOf<File>()
            val into = File(dest).apply { mkdirs() }
            suspend fun out(path: String, name: String, isDir: Boolean, size: Long, parent: File, top: Boolean): Reply? {
                if (!checkpoint()) return fail("cancelled")
                if (isDir) {
                    val folder = File(parent, if (top && !resume) PhoneFiles.freeName(parent, name) else name)
                    if (!folder.isDirectory && !folder.mkdirs()) return fail("io", "cannot create the folder $name")
                    for (e in parseEntries(Reply(QsCore.list(s.handle, path)).json)) {
                        out(childOf(path, e.name), e.name, e.dir, e.size, folder, false)?.let { return it }
                    }
                    return null
                }
                val target = File(parent, if (top && !resume) PhoneFiles.freeName(parent, name) else name)
                if (!(target.isFile && target.length() == size)) {
                    detail(name)
                    val pfd = runCatching { ParcelFileDescriptor.open(target, ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_TRUNCATE or ParcelFileDescriptor.MODE_WRITE_ONLY) }.getOrNull()
                        ?: return fail("io", "cannot write $name")
                    val r = pfd.use { Reply(QsCore.exportFile(s.handle, path, it.fd, progress(base, total))) }
                    if (!r.ok) {
                        target.delete()
                        return r
                    }
                    written += target
                }
                base += size
                files++
                return null
            }
            for (it in items) out(childOf(dir, it.name), it.name, it.dir, it.size, into, true)?.let { r -> PhoneFiles.rescan(written); return@work r }
            PhoneFiles.rescan(written)
            if (move) for (it in items) {
                val r = Reply(QsCore.remove(s.handle, childOf(dir, it.name)))
                if (!r.ok) return@work r
            }
            okReply((if (move) "نُقل" else "نُسخ") + " $files ${if (files == 1) "ملف" else "ملفات"} إلى الهاتف. تذكّر أنها غير مشفّرة هناك.")
        }
    }

    /** Deletes items of a folder. */
    fun delete(context: Context, s: Session, dir: String, names: List<String>, onEnd: ((Jobs.Job) -> Unit)? = null): Jobs.Job =
        Jobs.start(context, "delete", if (names.size == 1) "حذف «${names[0]}»" else "حذف ${names.size} عناصر", listOf(s.handle), onEnd = onEnd) work@{
            job.total = names.size.toLong()
            for ((i, n) in names.withIndex()) {
                if (!checkpoint()) return@work fail("cancelled")
                detail(n)
                val r = Reply(QsCore.remove(s.handle, childOf(dir, n)))
                if (!r.ok) return@work r
                job.done = (i + 1).toLong()
            }
            okReply("حُذف ${names.size} ${if (names.size == 1) "عنصر" else "عناصر"}.")
        }
}
