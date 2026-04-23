#ifdef __APPLE__
#include <GLUT/glut.h>
#else
#include <GL/glut.h>
#endif

#include <math.h>

// Global variables for transformations
float posX = 0.0, posY = 0.0, posZ = 0.0;
float rotation = 0.0f;
float scaleY = 1.0f;
int drawMode = GL_FILL;

// Camera variables
float camAlpha = 45.0f;   // Ângulo horizontal (ao redor do eixo Y)
float camBeta = 30.0f;    // Ângulo vertical
float camRadius = 10.0f;  // Distância da câmera à origem

// Mouse control variables
int mouseX, mouseY;
bool leftButtonPressed = false;
bool rightButtonPressed = false;

void changeSize(int w, int h) {

	// Prevent a divide by zero, when window is too short
	// (you cant make a window with zero width).
	if (h == 0)
		h = 1;

	// compute window's aspect ratio 
	float ratio = w * 1.0 / h;

	// Set the projection matrix as current
	glMatrixMode(GL_PROJECTION);
	// Load Identity Matrix
	glLoadIdentity();

	// Set the viewport to be the entire window
	glViewport(0, 0, w, h);

	// Set perspective
	gluPerspective(45.0f, ratio, 1.0f, 1000.0f);

	// return to the model view matrix mode
	glMatrixMode(GL_MODELVIEW);
}

void drawAxis() {
	glBegin(GL_LINES);
	// X axis in red
	glColor3f(1.0f, 0.0f, 0.0f);
	glVertex3f(-100.0f, 0.0f, 0.0f);
	glVertex3f(100.0f, 0.0f, 0.0f);

	// Y axis in green
	glColor3f(0.0f, 1.0f, 0.0f);
	glVertex3f(0.0f, -100.0f, 0.0f);
	glVertex3f(0.0f, 100.0f, 0.0f);

	// Z axis in blue
	glColor3f(0.0f, 0.0f, 1.0f);
	glVertex3f(0.0f, 0.0f, -100.0f);
	glVertex3f(0.0f, 0.0f, 100.0f);
	glEnd();
}

void drawPyramid() {
	glBegin(GL_TRIANGLES);
	// Front face - Red
	glColor3f(1.0f, 0.0f, 0.0f);
	glVertex3f(0.0f, 1.0f, 0.0f);
	glVertex3f(-1.0f, 0.0f, 1.0f);
	glVertex3f(1.0f, 0.0f, 1.0f);

	// Right face - Green
	glColor3f(0.0f, 1.0f, 0.0f);
	glVertex3f(0.0f, 1.0f, 0.0f);
	glVertex3f(1.0f, 0.0f, 1.0f);
	glVertex3f(1.0f, 0.0f, -1.0f);

	// Back face - Blue
	glColor3f(0.0f, 0.0f, 1.0f);
	glVertex3f(0.0f, 1.0f, 0.0f);
	glVertex3f(1.0f, 0.0f, -1.0f);
	glVertex3f(-1.0f, 0.0f, -1.0f);

	// Left face - Yellow
	glColor3f(1.0f, 1.0f, 0.0f);
	glVertex3f(0.0f, 1.0f, 0.0f);
	glVertex3f(-1.0f, 0.0f, -1.0f);
	glVertex3f(-1.0f, 0.0f, 1.0f);
	glEnd();

	// Base - Magenta
	glBegin(GL_QUADS);
	glColor3f(1.0f, 0.0f, 1.0f);
	glVertex3f(-1.0f, 0.0f, -1.0f);
	glVertex3f(1.0f, 0.0f, -1.0f);
	glVertex3f(1.0f, 0.0f, 1.0f);
	glVertex3f(-1.0f, 0.0f, 1.0f);
	glEnd();
}

void renderScene(void) {

	// clear buffers
	glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

	// set the camera - usando coordenadas esféricas
	glLoadIdentity();

	// Calcular posição da câmera usando ângulos esféricos
	float camX = camRadius * cos(camBeta * 3.14159f / 180.0f) * sin(camAlpha * 3.14159f / 180.0f);
	float camY = camRadius * sin(camBeta * 3.14159f / 180.0f);
	float camZ = camRadius * cos(camBeta * 3.14159f / 180.0f) * cos(camAlpha * 3.14159f / 180.0f);

	gluLookAt(camX, camY, camZ,    // Posição da câmera
		0.0, 0.0, 0.0,       // Look at point
		0.0, 1.0, 0.0);      // Up vector

	// DA
	drawAxis();

	// move object
	glTranslatef(posX, 0.0f, posZ);
	glRotatef(rotation, 0.0f, 1.0f, 0.0f);
	glScalef(1.0f, scaleY, 1.0f);

	// put pyramid drawing instructions here
	glPolygonMode(GL_FRONT_AND_BACK, drawMode);
	drawPyramid();

	// End of frame
	glutSwapBuffers();
}

// Callback para cliques do mouse
void processMouse(int button, int state, int x, int y) {
	if (button == GLUT_LEFT_BUTTON) {
		if (state == GLUT_DOWN) {
			leftButtonPressed = true;
			mouseX = x;
			mouseY = y;
		}
		else {
			leftButtonPressed = false;
		}
	}

	if (button == GLUT_RIGHT_BUTTON) {
		if (state == GLUT_DOWN) {
			rightButtonPressed = true;
			mouseX = x;
			mouseY = y;
		}
		else {
			rightButtonPressed = false;
		}
	}

	// Scroll do mouse para zoom
	if (button == 3) { // Scroll up
		camRadius -= 0.5f;
		if (camRadius < 2.0f) camRadius = 2.0f;
		glutPostRedisplay();
	}
	else if (button == 4) { // Scroll down
		camRadius += 0.5f;
		if (camRadius > 50.0f) camRadius = 50.0f;
		glutPostRedisplay();
	}
}

// Callback para movimento do mouse
void processMouseMotion(int x, int y) {
	if (leftButtonPressed) {
		// Rotação da câmera
		camAlpha += (x - mouseX) * 0.5f;
		camBeta += (y - mouseY) * 0.5f;

		// Limitar ângulo beta para evitar flip
		if (camBeta > 89.0f) camBeta = 89.0f;
		if (camBeta < -89.0f) camBeta = -89.0f;

		mouseX = x;
		mouseY = y;
		glutPostRedisplay();
	}

	if (rightButtonPressed) {
		// Zoom alternativo com botão direito
		camRadius += (y - mouseY) * 0.1f;
		if (camRadius < 2.0f) camRadius = 2.0f;
		if (camRadius > 50.0f) camRadius = 50.0f;

		mouseY = y;
		glutPostRedisplay();
	}
}

// write function to process keyboard events
void processKeys(unsigned char key, int x, int y) {
	switch (key) {
		// Movement in XZ plane
	case 'w':
	case 'W':
		posZ -= 0.2f;
		break;
	case 's':
	case 'S':
		posZ += 0.2f;
		break;
	case 'a':
	case 'A':
		posX -= 0.2f;
		break;
	case 'd':
	case 'D':
		posX += 0.2f;
		break;

		// Rotation around Y axis (vertical axis)
	case 'q':
	case 'Q':
		rotation -= 5.0f;
		break;
	case 'e':
	case 'E':
		rotation += 5.0f;
		break;

		// Scale height
	case 'r':
	case 'R':
		scaleY += 0.1f;
		break;
	case 'f':
	case 'F':
		scaleY -= 0.1f;
		break;

		// Drawing modes
	case '1':
		drawMode = GL_FILL;
		break;
	case '2':
		drawMode = GL_LINE;
		break;
	case '3':
		drawMode = GL_POINT;
		break;

		// Reset transformations
	case ' ':
		posX = posZ = rotation = 0.0f;
		scaleY = 1.0f;
		camAlpha = 45.0f;
		camBeta = 30.0f;
		camRadius = 10.0f;
		break;

		// Exit
	case 27: // ESC key
		exit(0);
		break;
	}

	// Request display update
	glutPostRedisplay();
}

int main(int argc, char** argv) {

	// init GLUT and the window
	glutInit(&argc, argv);
	glutInitDisplayMode(GLUT_DEPTH | GLUT_DOUBLE | GLUT_RGBA);
	glutInitWindowPosition(100, 100);
	glutInitWindowSize(800, 800);
	glutCreateWindow("CG@DI-UM");

	// Required callback registry 
	glutDisplayFunc(renderScene);
	glutReshapeFunc(changeSize);

	// put here the registration of the keyboard callbacks
	glutKeyboardFunc(processKeys);

	// Registar callbacks do mouse
	glutMouseFunc(processMouse);
	glutMotionFunc(processMouseMotion);

	//  OpenGL settings
	glEnable(GL_DEPTH_TEST);
	glEnable(GL_CULL_FACE);

	// enter GLUT's main cycle
	glutMainLoop();

	return 1;
}