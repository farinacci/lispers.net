// Generates the app icon in the style of the lispers.net logo:
// black field, atom-orbit ellipses, green "lispers" + red ".net".
// Run: swift make-icon.swift <output.png>

import AppKit

let size = CGFloat(1024)
let image = NSImage(size: NSSize(width: size, height: size))
image.lockFocus()

let ctx = NSGraphicsContext.current!.cgContext

// Black background
ctx.setFillColor(NSColor.black.cgColor)
ctx.fill(CGRect(x: 0, y: 0, width: size, height: size))

// Atom orbits — three rotated ellipses + a small one, light gray strokes
ctx.setStrokeColor(NSColor(white: 0.72, alpha: 0.85).cgColor)
ctx.setLineWidth(5.0)
let center = CGPoint(x: size / 2, y: size / 2)
for angle in [CGFloat(0), 60, 120] {
    ctx.saveGState()
    ctx.translateBy(x: center.x, y: center.y)
    ctx.rotate(by: angle * .pi / 180)
    ctx.strokeEllipse(in: CGRect(x: -430, y: -200, width: 860, height: 400))
    ctx.restoreGState()
}
ctx.strokeEllipse(in: CGRect(x: center.x - 260, y: center.y - 260,
                             width: 520, height: 520))

// Wordmark
func draw(_ text: String, color: NSColor, fontSize: CGFloat, at point: CGPoint,
          shadow: Bool = false) -> CGFloat {
    let font = NSFont(name: "Times-BoldItalic", size: fontSize)
        ?? NSFont.boldSystemFont(ofSize: fontSize)
    var attrs: [NSAttributedString.Key: Any] = [
        .font: font, .foregroundColor: color
    ]
    if shadow {
        // Dark halo so white text stays readable over the orbital lines.
        let sh = NSShadow()
        sh.shadowColor = NSColor.black
        sh.shadowBlurRadius = 10
        sh.shadowOffset = .zero
        attrs[.shadow] = sh
    }
    let s = NSAttributedString(string: text, attributes: attrs)
    s.draw(at: point)
    return s.size().width
}

// Width of a string without drawing it (for centering).
func textWidth(_ text: String, fontSize: CGFloat) -> CGFloat {
    let font = NSFont(name: "Times-BoldItalic", size: fontSize)
        ?? NSFont.boldSystemFont(ofSize: fontSize)
    return NSAttributedString(string: text, attributes: [.font: font]).size().width
}

let green = NSColor(calibratedRed: 0.18, green: 0.58, blue: 0.16, alpha: 1)
let red = NSColor(calibratedRed: 0.82, green: 0.10, blue: 0.10, alpha: 1)

// "lispers.net" centered horizontally in the square. The ".' tucks 12px left,
// so the visual width is the three pieces minus that overlap.
let wordFont = CGFloat(215)
let wordWidth = textWidth("lispers", fontSize: wordFont)
              + textWidth(".", fontSize: wordFont)
              + textWidth("net", fontSize: wordFont) - 12
let baseY = CGFloat(430)
var x = (size - wordWidth) / 2
x += draw("lispers", color: green, fontSize: wordFont, at: CGPoint(x: x, y: baseY))
x += draw(".", color: NSColor.white, fontSize: wordFont, at: CGPoint(x: x - 12, y: baseY)) - 12
_ = draw("net", color: red, fontSize: wordFont, at: CGPoint(x: x, y: baseY))

// Subtitle, also centered, with a shadow for readability over the orbits.
let subFont = CGFloat(50)
let subText = "Scalable Open Overlay Networking"
_ = draw(subText, color: .white, fontSize: subFont,
         at: CGPoint(x: (size - textWidth(subText, fontSize: subFont)) / 2, y: 360),
         shadow: true)

image.unlockFocus()

guard let tiff = image.tiffRepresentation,
      let rep = NSBitmapImageRep(data: tiff),
      let png = rep.representation(using: .png, properties: [:]) else {
    fatalError("Could not render PNG")
}
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.png"
try! png.write(to: URL(fileURLWithPath: out))
print("Wrote \(out)")
